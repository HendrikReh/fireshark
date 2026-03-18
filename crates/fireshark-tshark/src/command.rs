use std::path::Path;
use std::process::Command;

use crate::TsharkError;

/// The tshark fields extracted via `-T fields`.
///
/// Order must match the `-e` flags passed to tshark in [`run_fields`].
pub const FIELD_NAMES: &[&str] = &[
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.cap_len",
    "_ws.col.Protocol",
    "_ws.col.Info",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
];

/// Run tshark with `-T fields` output on the given capture file.
///
/// Returns the raw TSV stdout (header line + one data line per packet).
///
/// # Safety
///
/// `capture_path` is passed to `Command::arg`, which hands it directly to
/// `execve` without shell interpretation. This is safe from command injection
/// even if the path contains spaces, semicolons, or other shell metacharacters.
pub fn run_fields(tshark_path: &Path, capture_path: &Path) -> Result<String, TsharkError> {
    let mut cmd = Command::new(tshark_path);
    cmd.arg("-r").arg(capture_path);
    cmd.arg("-T").arg("fields");
    cmd.arg("-E").arg("separator=\t");
    cmd.arg("-E").arg("header=y");

    for field in FIELD_NAMES {
        cmd.arg("-e").arg(field);
    }

    let output = cmd
        .output()
        .map_err(|e| TsharkError::Execution(format!("failed to spawn tshark: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(TsharkError::Execution(format!(
            "tshark exited with {}: {}",
            output.status,
            stderr.trim()
        )));
    }

    String::from_utf8(output.stdout)
        .map_err(|e| TsharkError::ParseOutput(format!("tshark output is not valid UTF-8: {e}")))
}
