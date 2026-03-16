use std::path::Path;

use fireshark_core::Pipeline;
use fireshark_dissectors::decode_packet;
use fireshark_file::CaptureReader;

use crate::color;
use crate::timestamp;

pub fn run(path: &Path, filter: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let filter_expr = filter.map(fireshark_filter::parse).transpose()?;

    let reader = CaptureReader::open(path)?;
    for (index, decoded) in Pipeline::new(reader, decode_packet).enumerate() {
        let decoded = match decoded {
            Ok(d) => d,
            Err(e) => {
                eprintln!("warning: packet {}: {e}", index + 1);
                continue;
            }
        };

        if let Some(ref expr) = filter_expr
            && !fireshark_filter::evaluate(expr, &decoded)
        {
            continue;
        }

        let summary = decoded.summary();
        let ts = match summary.timestamp {
            Some(duration) => timestamp::format_utc(duration),
            None => String::from("-"),
        };
        let line = format!(
            "{:>4}  {:<24}  {:<5}  {:<22} -> {:<22} {:>4}",
            index + 1,
            ts,
            summary.protocol,
            summary.source,
            summary.destination,
            summary.length
        );
        println!("{}", color::colorize(&summary.protocol, &line));
    }

    Ok(())
}
