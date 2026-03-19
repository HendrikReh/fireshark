use std::io::Read;
use std::path::Path;
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

use crate::TsharkError;

/// Default timeout for tshark subprocess execution (5 minutes).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

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

    let output = run_with_timeout(cmd, DEFAULT_TIMEOUT)?;

    String::from_utf8(output.stdout)
        .map_err(|e| TsharkError::ParseOutput(format!("tshark output is not valid UTF-8: {e}")))
}

/// Spawn a command with a timeout. Kills the child if it exceeds the deadline.
pub fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Result<Output, TsharkError> {
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| TsharkError::Execution(format!("failed to spawn tshark: {e}")))?;

    let mut stdout_handle = child.stdout.take().map(|mut stdout| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stdout.read_to_end(&mut buf);
            buf
        })
    });
    let mut stderr_handle = child.stderr.take().map(|mut stderr| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stderr.read_to_end(&mut buf);
            buf
        })
    });

    let deadline = std::time::Instant::now() + timeout;
    let poll_interval = Duration::from_millis(100);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = join_output(stdout_handle.take())?;
                let stderr = join_output(stderr_handle.take())?;

                if !status.success() {
                    let stderr_str = String::from_utf8_lossy(&stderr);
                    return Err(TsharkError::Execution(format!(
                        "tshark exited with {}: {}",
                        status,
                        stderr_str.trim()
                    )));
                }

                return Ok(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                // Still running — check deadline.
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = join_output(stdout_handle.take());
                    let _ = join_output(stderr_handle.take());
                    return Err(TsharkError::Execution(format!(
                        "tshark timed out after {}s",
                        timeout.as_secs()
                    )));
                }
                std::thread::sleep(poll_interval);
            }
            Err(e) => {
                return Err(TsharkError::Execution(format!(
                    "failed to wait for tshark: {e}"
                )));
            }
        }
    }
}

fn join_output(
    handle: Option<thread::JoinHandle<Vec<u8>>>,
) -> Result<Vec<u8>, TsharkError> {
    match handle {
        Some(handle) => handle
            .join()
            .map_err(|_| TsharkError::Execution("failed to join tshark output reader".into())),
        None => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn run_with_timeout_drains_stdout_while_child_runs() {
        let mut cmd = Command::new("dd");
        cmd.arg("if=/dev/zero").arg("bs=1024").arg("count=128");

        let output = run_with_timeout(cmd, Duration::from_secs(2))
            .expect("child writing 128 KiB should complete before timeout");

        assert_eq!(output.stdout.len(), 128 * 1024);
    }
}
