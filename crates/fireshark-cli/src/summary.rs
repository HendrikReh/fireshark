use std::path::Path;

use fireshark_core::Pipeline;
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

pub fn run(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let reader = CaptureReader::open(path)?;
    for (index, decoded) in Pipeline::new(reader, decode_packet).enumerate() {
        let decoded = decoded?;
        let summary = decoded.summary();
        println!(
            "{:>4}  {:<5}  {:<22} -> {:<22} {:>4}",
            index + 1,
            summary.protocol,
            summary.source,
            summary.destination,
            summary.length
        );
    }

    Ok(())
}
