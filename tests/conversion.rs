use ccitocia::{Stage, convert, convert_with_progress};
use sha2::{Digest, Sha256};
use std::fs;

fn put32(b: &mut [u8], p: usize, v: u32) {
    b[p..p + 4].copy_from_slice(&v.to_le_bytes());
}
fn valid_fixture(indices: &[usize]) -> Vec<u8> {
    let mut rom = vec![0; 0x4000 + indices.len() * 0x5000];
    rom[0x100..0x104].copy_from_slice(b"NCSD");
    rom[0x108..0x110].copy_from_slice(&0x0004000000123400u64.to_le_bytes());
    for (n, &i) in indices.iter().enumerate() {
        let start = 0x4000 + n * 0x5000;
        put32(&mut rom, 0x120 + i * 8, (start / 512) as u32);
        put32(&mut rom, 0x124 + i * 8, 0x28);
        let p = &mut rom[start..start + 0x5000];
        p[0x100..0x104].copy_from_slice(b"NCCH");
        put32(p, 0x104, 0x28);
        p[0x118..0x120].copy_from_slice(&0x0004000000123400u64.to_le_bytes());
        p[0x18f] = 4;
        if i == 0 {
            put32(p, 0x180, 0x400);
            let hash = Sha256::digest(&p[0x200..0x600]);
            p[0x160..0x180].copy_from_slice(&hash);
            put32(p, 0x1a0, 5);
            put32(p, 0x1a4, 0x1d);
            // Last ExeFS entry tests that all ten slots are searched.
            p[0xa90..0xa98].copy_from_slice(b"icon\0\0\0\0");
            put32(p, 0xa9c, 0x36c0);
            p[0xc00..0xc04].copy_from_slice(b"SMDH");
        }
    }
    rom
}

#[test]
fn layout_hashes_and_sparse_indices() {
    for indices in [&[0][..], &[0, 1], &[0, 2], &[0, 1, 2], &[0, 1, 2, 7]] {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("game.cci");
        let output = dir.path().join("game.cia");
        let rom = valid_fixture(indices);
        fs::write(&input, &rom).unwrap();
        let summary = convert(&input, &output).unwrap();
        let ids: Vec<_> = indices.iter().copied().filter(|i| *i < 3).collect();
        assert_eq!(summary.contents, ids.len());
        let cia = fs::read(&output).unwrap();
        assert_eq!(cia[0x20], ids.iter().fold(0, |b, i| b | (0x80 >> i)));
        assert_eq!(&cia[0x2c1c..0x2c24], &0x0004000000123400u64.to_be_bytes());
        let tmd = &cia[0x2dc0..0x2dc0 + 0xb04 + ids.len() * 48];
        assert_eq!(Sha256::digest(&tmd[0x204..0xb04])[..], tmd[0x1e4..0x204]);
        assert_eq!(Sha256::digest(&tmd[0xb04..])[..], tmd[0x208..0x228]);
        let content_start = (0x2dc0 + tmd.len() + 63) & !63;
        for (n, id) in ids.iter().enumerate() {
            let content = &cia[content_start + n * 0x5000..content_start + (n + 1) * 0x5000];
            let record = &tmd[0xb04 + n * 48..0xb04 + (n + 1) * 48];
            assert_eq!(&record[4..6], &(*id as u16).to_be_bytes());
            assert_eq!(Sha256::digest(content)[..], record[16..48]);
            if *id == 0 {
                assert_eq!(content[0x20d] & 2, 2);
                assert_eq!(
                    Sha256::digest(&content[0x200..0x600])[..],
                    content[0x160..0x180]
                );
            }
        }
        assert_eq!(cia.len(), content_start + ids.len() * 0x5000 + 0x3ac0);
        assert_eq!(&cia[cia.len() - 0x36c0..cia.len() - 0x36c0 + 4], b"SMDH");
        assert_eq!(fs::read(&input).unwrap(), rom);
        assert!(convert(&input, &output).is_err());
        assert_eq!(fs::read(&output).unwrap(), cia);
    }
}

#[test]
fn rejects_bad_inputs_without_output() {
    for case in 0..7 {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("bad.cci");
        let output = dir.path().join("bad.cia");
        let mut rom = valid_fixture(&[0, 1]);
        match case {
            0 => rom[0x100] = 0,
            1 => rom.truncate(0x4100),
            2 => rom[0x418f] = 0,
            3 => rom[0x918f] = 0,
            4 => rom[0x4200] ^= 1,
            5 => put32(&mut rom, 0x128, 0x20),
            _ => put32(&mut rom, 0x4a98, u32::MAX),
        }
        fs::write(&input, rom).unwrap();
        let mut events = Vec::new();
        assert!(
            convert_with_progress(&input, &output, |p| events.push(p)).is_err(),
            "case {case}"
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].stage, Stage::Validating);
        assert!(!output.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

#[test]
fn progress_counts_payloads_across_partitions_and_reports_publication() {
    for indices in [&[0][..], &[0, 2], &[0, 1, 2, 7]] {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("game.cci");
        let output = dir.path().join("game.cia");
        fs::write(&input, valid_fixture(indices)).unwrap();
        let mut events = Vec::new();
        let summary = convert_with_progress(&input, &output, |p| {
            // Publishing is the final operation, after both copying and metadata.
            assert_eq!(output.exists(), p.stage == Stage::Complete);
            events.push(p);
        })
        .unwrap();
        let expected_total = indices.iter().filter(|&&i| i < 3).count() as u64 * 0x5000;
        assert_eq!(summary.content_bytes, expected_total);
        assert_eq!(events[0].stage, Stage::Validating);
        assert_eq!(events[0].bytes_written, 0);
        assert_eq!(events[0].total_bytes, 0);
        let finalizing = events.len() - 2;
        assert_eq!(events[finalizing].stage, Stage::Finalizing);
        assert_eq!(events.last().unwrap().stage, Stage::Complete);
        assert!(
            events[1..finalizing]
                .iter()
                .all(|p| p.stage == Stage::Copying)
        );
        assert!(events[1..].iter().all(|p| p.total_bytes == expected_total));
        assert!(
            events
                .windows(2)
                .all(|w| w[0].bytes_written <= w[1].bytes_written)
        );
        // Both patched header writes contribute to progress immediately.
        assert_eq!(events[1].bytes_written, 0);
        assert_eq!(events[2].bytes_written, 0x200);
        assert_eq!(events[3].bytes_written, 0x600);
        for n in 1..=summary.contents {
            assert_eq!(events[n + 3].bytes_written, n as u64 * 0x5000);
        }
        assert!(
            events[finalizing..]
                .iter()
                .all(|p| p.bytes_written == expected_total)
        );
    }
}

#[test]
fn large_payload_reports_incremental_progress() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("large.cci");
    let output = dir.path().join("large.cia");
    let size = 0x305000;
    let mut rom = valid_fixture(&[0]);
    rom.resize(0x4000 + size, 0);
    put32(&mut rom, 0x124, (size / 512) as u32);
    put32(&mut rom, 0x4104, (size / 512) as u32);
    fs::write(&input, rom).unwrap();
    let mut counts = Vec::new();
    convert_with_progress(&input, &output, |p| {
        if p.stage == Stage::Copying {
            counts.push(p.bytes_written);
        }
    })
    .unwrap();
    assert_eq!(counts.last(), Some(&(size as u64)));
    assert!(counts.len() > 5);
    assert!(
        counts
            .windows(2)
            .all(|w| w[1] > w[0] && w[1] - w[0] <= 1024 * 1024)
    );
}

#[test]
fn publishing_failure_never_reports_complete_or_replaces_existing_output() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("game.cci");
    let output = dir.path().join("game.cia");
    fs::write(&input, valid_fixture(&[0])).unwrap();
    let mut stages = Vec::new();
    let error = convert_with_progress(&input, &output, |p| {
        stages.push(p.stage);
        if p.stage == Stage::Finalizing {
            fs::write(&output, b"existing file").unwrap();
        }
    })
    .unwrap_err();
    assert!(error.to_string().contains("Cannot publish output"));
    assert_eq!(stages.last(), Some(&Stage::Finalizing));
    assert!(!stages.contains(&Stage::Complete));
    assert_eq!(fs::read(&output).unwrap(), b"existing file");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}
