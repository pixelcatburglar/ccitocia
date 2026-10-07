use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = "Convert a decrypted CCI/.3ds image to an unsigned CIA for custom firmware"
)]
struct Args {
    /// Decrypted cartridge image
    input: PathBuf,
    /// Destination (defaults to the input filename with a .cia extension); never overwritten
    #[arg(short, long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let output = args
        .output
        .unwrap_or_else(|| args.input.with_extension("cia"));
    eprintln!("Converting {} ...", args.input.display());
    let summary = ccitocia::convert(&args.input, &output).context("Conversion failed")?;
    eprintln!(
        "Created {} (title {:016X}, {} contents, {} content bytes)",
        output.display(),
        summary.title_id,
        summary.contents,
        summary.content_bytes
    );
    Ok(())
}
