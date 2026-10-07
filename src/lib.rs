//! Native, bounded-memory CCI packaging. Input NCCH contents must be decrypted.
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

const MU: u64 = 0x200;
const CERT: &[u8] = include_bytes!("../assets/certchain_retail.bin");
const TEMPLATE: &[u8] = include_bytes!("../assets/ticket_tmd.bin");

#[derive(Debug)]
pub struct Summary {
    pub title_id: u64,
    pub contents: usize,
    pub content_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Validating,
    Copying,
    Finalizing,
    Complete,
}

/// Conversion status. Byte counts describe content payloads, excluding CIA metadata.
/// The total is unknown (zero) during validation. A full byte count alone does not
/// mean success: only `Stage::Complete` confirms that the output was published.
#[derive(Debug, Clone, Copy)]
pub struct Progress {
    pub stage: Stage,
    pub bytes_written: u64,
    pub total_bytes: u64,
}

fn le32(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
}
fn le64(b: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(b[p..p + 8].try_into().unwrap())
}
fn read_at(f: &mut File, offset: u64, len: usize) -> Result<Vec<u8>> {
    f.seek(SeekFrom::Start(offset))?;
    let mut data = vec![0; len];
    f.read_exact(&mut data)?;
    Ok(data)
}
fn pad(f: &mut File) -> Result<()> {
    let n = (64 - f.stream_position()? % 64) % 64;
    f.write_all(&[0; 64][..n as usize])?;
    Ok(())
}
struct Part {
    index: u16,
    offset: u64,
    size: u64,
    header: Vec<u8>,
}

/// Writes via a temporary file in the destination directory, publishing only on success.
/// Existing destinations are never replaced. Update partitions are deliberately omitted.
pub fn convert(input: &Path, output: &Path) -> Result<Summary> {
    convert_with_progress(input, output, |_| {})
}

/// Converts an image while reporting progress synchronously on the calling thread.
/// Errors are returned to the caller; failed conversions never report `Complete`.
/// Writes via a temporary file and never replaces an existing destination.
pub fn convert_with_progress(
    input: &Path,
    output: &Path,
    mut on_progress: impl FnMut(Progress),
) -> Result<Summary> {
    on_progress(Progress {
        stage: Stage::Validating,
        bytes_written: 0,
        total_bytes: 0,
    });
    ensure!(
        !output.exists(),
        "Destination already exists: {}",
        output.display()
    );
    let mut source = File::open(input).context("Cannot open input")?;
    let length = source.metadata()?.len();
    let ncsd = read_at(&mut source, 0, 0x200).context("Truncated NCSD header")?;
    ensure!(
        &ncsd[0x100..0x104] == b"NCSD",
        "Missing NCSD magic; expected a CCI/.3ds image"
    );
    ensure!(
        ncsd[0x110..0x118].iter().all(|&b| b == 0),
        "NAND images are unsupported"
    );
    ensure!(ncsd[0x18e] == 0, "Unsupported NCSD media unit size");
    let title_id = le64(&ncsd, 0x108);
    let mut parts = Vec::new();
    let mut ranges = Vec::new();
    for i in 0..8 {
        let offset = u64::from(le32(&ncsd, 0x120 + i * 8)) * MU;
        let size = u64::from(le32(&ncsd, 0x124 + i * 8)) * MU;
        if offset == 0 && size == 0 {
            continue;
        }
        ensure!(
            offset >= 0x200 && size >= MU && offset + size <= length,
            "Partition {i} is truncated or has invalid bounds"
        );
        ensure!(
            ranges
                .iter()
                .all(|&(s, e)| offset >= e || offset + size <= s),
            "Overlapping partitions"
        );
        ranges.push((offset, offset + size));
        if i > 2 {
            continue;
        }
        let header = read_at(&mut source, offset, 0x200)?;
        ensure!(
            &header[0x100..0x104] == b"NCCH",
            "Partition {i}: missing NCCH magic"
        );
        ensure!(
            header[0x18e] == 0,
            "Partition {i}: unsupported NCCH unit size"
        );
        ensure!(
            u64::from(le32(&header, 0x104)) * MU == size,
            "Partition {i}: NCCH and NCSD sizes differ"
        );
        ensure!(
            header[0x18f] & 4 != 0,
            "Partition {i} is encrypted. Supply a decrypted CCI image; key-based decryption is not implemented"
        );
        parts.push(Part {
            index: i as u16,
            offset,
            size,
            header,
        });
    }
    ensure!(
        !parts.is_empty() && parts[0].index == 0,
        "Missing application partition 0"
    );
    let game = &mut parts[0];
    ensure!(
        le64(&game.header, 0x118) == title_id,
        "Application program ID differs from NCSD title ID"
    );
    ensure!(
        le32(&game.header, 0x180) == 0x400 && game.size >= 0xa00,
        "Unsupported application extended header"
    );
    let mut exheader = read_at(&mut source, game.offset + MU, 0x400)?;
    ensure!(
        Sha256::digest(&exheader)[..] == game.header[0x160..0x180],
        "Invalid application extended-header SHA-256"
    );
    exheader[0x0d] |= 2; // SD application flag
    game.header[0x160..0x180].copy_from_slice(&Sha256::digest(&exheader));
    let exefs = u64::from(le32(&game.header, 0x1a0)) * MU;
    let exefs_size = u64::from(le32(&game.header, 0x1a4)) * MU;
    ensure!(
        exefs >= 0xa00 && exefs_size >= MU && exefs + exefs_size <= game.size,
        "Invalid ExeFS bounds"
    );
    let entries = read_at(&mut source, game.offset + exefs, 0x200)?;
    let mut icon = None;
    for entry in entries[..0xa0].chunks_exact(16) {
        if &entry[..8] != b"icon\0\0\0\0" {
            continue;
        }
        let start = u64::from(le32(entry, 8)) + MU;
        ensure!(
            le32(entry, 12) == 0x36c0 && start + 0x36c0 <= exefs_size,
            "Invalid ExeFS icon bounds"
        );
        let data = read_at(&mut source, game.offset + exefs + start, 0x36c0)?;
        ensure!(&data[..4] == b"SMDH", "Invalid icon SMDH magic");
        icon = Some(data);
        break;
    }
    let icon = icon.context("Application ExeFS has no SMDH icon")?;
    let count = parts.len();
    let total: u64 = parts.iter().map(|p| p.size).sum();
    let tmd_size = 0xb04 + count * 0x30;
    let mut header = vec![0; 0x2020];
    header[..4].copy_from_slice(&0x2020u32.to_le_bytes());
    header[8..12].copy_from_slice(&(CERT.len() as u32).to_le_bytes());
    header[12..16].copy_from_slice(&0x350u32.to_le_bytes());
    header[16..20].copy_from_slice(&(tmd_size as u32).to_le_bytes());
    header[20..24].copy_from_slice(&0x3ac0u32.to_le_bytes());
    header[24..32].copy_from_slice(&total.to_le_bytes());
    for p in &parts {
        header[32 + p.index as usize / 8] |= 0x80 >> (p.index % 8);
    }
    // The attributed template contains a 0x350 ticket, alignment, then TMD prefix.
    let mut ticket = TEMPLATE[..0x350].to_vec();
    ticket[0x1dc..0x1e4].copy_from_slice(&title_id.to_be_bytes());
    let mut tmd = vec![0; tmd_size];
    tmd[..TEMPLATE.len() - 0x380].copy_from_slice(&TEMPLATE[0x380..]);
    tmd[0x18c..0x194].copy_from_slice(&title_id.to_be_bytes());
    tmd[0x19a..0x19e].copy_from_slice(&exheader[0x1c0..0x1c4]);
    tmd[0x1de..0x1e0].copy_from_slice(&(count as u16).to_be_bytes());
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temp =
        tempfile::NamedTempFile::new_in(parent).context("Cannot create temporary output")?;
    let dest = temp.as_file_mut();
    dest.write_all(&header)?;
    pad(dest)?;
    dest.write_all(CERT)?;
    pad(dest)?;
    dest.write_all(&ticket)?;
    pad(dest)?;
    let tmd_offset = dest.stream_position()?;
    dest.write_all(&tmd)?;
    pad(dest)?;
    let mut buffer = vec![0; 1024 * 1024];
    let mut bytes_written = 0;
    on_progress(Progress {
        stage: Stage::Copying,
        bytes_written,
        total_bytes: total,
    });
    for (n, part) in parts.iter().enumerate() {
        let mut hash = Sha256::new();
        let mut copied = 0;
        if part.index == 0 {
            for bytes in [&part.header[..], &exheader[..]] {
                dest.write_all(bytes)?;
                hash.update(bytes);
                bytes_written += bytes.len() as u64;
                on_progress(Progress {
                    stage: Stage::Copying,
                    bytes_written,
                    total_bytes: total,
                });
            }
            copied = 0x600;
        }
        source.seek(SeekFrom::Start(part.offset + copied))?;
        while copied < part.size {
            let take = (part.size - copied).min(buffer.len() as u64) as usize;
            source.read_exact(&mut buffer[..take])?;
            dest.write_all(&buffer[..take])?;
            hash.update(&buffer[..take]);
            copied += take as u64;
            bytes_written += take as u64;
            on_progress(Progress {
                stage: Stage::Copying,
                bytes_written,
                total_bytes: total,
            });
        }
        let record = &mut tmd[0xb04 + n * 0x30..0xb04 + (n + 1) * 0x30];
        record[..4].copy_from_slice(&u32::from(part.index).to_be_bytes());
        record[4..6].copy_from_slice(&part.index.to_be_bytes());
        record[8..16].copy_from_slice(&part.size.to_be_bytes());
        record[16..].copy_from_slice(&hash.finalize());
    }
    on_progress(Progress {
        stage: Stage::Finalizing,
        bytes_written,
        total_bytes: total,
    });
    let chunk_hash = Sha256::digest(&tmd[0xb04..]);
    tmd[0x206..0x208].copy_from_slice(&(count as u16).to_be_bytes());
    tmd[0x208..0x228].copy_from_slice(&chunk_hash);
    let info_hash = Sha256::digest(&tmd[0x204..0xb04]);
    tmd[0x1e4..0x204].copy_from_slice(&info_hash);
    pad(dest)?;
    let mut meta = vec![0; 0x3ac0];
    meta[..0x180].copy_from_slice(&exheader[0x40..0x1c0]);
    meta[0x300..0x304].copy_from_slice(&2u32.to_le_bytes());
    meta[0x400..].copy_from_slice(&icon);
    dest.write_all(&meta)?;
    dest.seek(SeekFrom::Start(tmd_offset))?;
    dest.write_all(&tmd)?;
    dest.sync_all()?;
    temp.persist_noclobber(output)
        .map_err(|e| e.error)
        .context("Cannot publish output (destination may already exist)")?;
    on_progress(Progress {
        stage: Stage::Complete,
        bytes_written,
        total_bytes: total,
    });
    Ok(Summary {
        title_id,
        contents: count,
        content_bytes: total,
    })
}
