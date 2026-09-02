pub mod gau;
pub mod httpx;
pub mod js_miner;
pub mod katana;
pub mod subfinder;

use crate::errors::{BountyScopeError, Result};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tracing::{debug, error, info, warn};

pub use gau::GauRunner;
pub use httpx::{HttpProbeResult, HttpxRunner};
pub use js_miner::{JsMiner, JsMinerResult};
pub use katana::KatanaRunner;
pub use subfinder::{SubdomainResult, SubfinderRunner};


/// Safe asynchronous process executor without shell interpolation
pub struct ProcessExecutor;

impl ProcessExecutor {
    pub async fn execute(
        binary: &str,
        args: &[&str],
        input_data: Option<&str>,
        timeout: Duration,
    ) -> Result<(String, String)> {
        debug!(
            "Spawning process '{}' with args: {:?}",
            binary, args
        );

        let mut cmd = Command::new(binary);
        cmd.args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        if input_data.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }

        let mut child = cmd.spawn().map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                BountyScopeError::MissingBinary(binary.to_string())
            } else {
                BountyScopeError::Io(err)
            }
        })?;

        // Pipe stdin if provided
        if let Some(input) = input_data {
            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                let _ = stdin.write_all(input.as_bytes()).await;
                let _ = stdin.shutdown().await;
            }
        }

        // Wait with timeout
        let wait_result = tokio::time::timeout(timeout, child.wait_with_output()).await;

        match wait_result {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();

                if !output.status.success() {
                    let code = output.status.code();
                    // Some tools (like grep or nuclei with no findings) exit with 1; we return output with warning
                    debug!(
                        "Process '{}' exited with non-zero code {:?}. Stderr: {}",
                        binary, code, stderr
                    );
                }

                Ok((stdout, stderr))
            }
            Ok(Err(io_err)) => {
                error!("I/O error during execution of '{}': {}", binary, io_err);
                Err(BountyScopeError::Io(io_err))
            }
            Err(_) => {
                warn!(
                    "Process '{}' timed out after {:?}. Killing process.",
                    binary, timeout
                );
                Err(BountyScopeError::ProcessTimeout {
                    binary: binary.to_string(),
                    timeout_secs: timeout.as_secs(),
                })
            }
        }
    }
}
