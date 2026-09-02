use crate::database::repository::Repository;
use crate::errors::{BountyScopeError, Result};
use crate::tools::adapter::ToolOutput;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{debug, error, warn};

pub struct SafeProcessExecutor;

impl SafeProcessExecutor {
    pub async fn execute(
        tool_name: &str,
        binary: &str,
        args: &[&str],
        input_data: Option<&str>,
        timeout_duration: Duration,
        repo: Option<&Repository>,
        job_id: Option<&str>,
        target: &str,
    ) -> Result<ToolOutput> {
        Self::execute_cancellable(
            tool_name,
            binary,
            args,
            input_data,
            timeout_duration,
            repo,
            job_id,
            target,
            None,
        )
        .await
    }

    pub async fn execute_cancellable(
        tool_name: &str,
        binary: &str,
        args: &[&str],
        input_data: Option<&str>,
        timeout_duration: Duration,
        repo: Option<&Repository>,
        job_id: Option<&str>,
        target: &str,
        cancel_token: Option<&tokio_util::sync::CancellationToken>,
    ) -> Result<ToolOutput> {
        let command_args_str = args.join(" ");
        debug!(
            "Spawning tool '{}' ({}) with args: [{}]",
            tool_name, binary, command_args_str
        );

        // Record start in tool_runs if repository is provided
        let run_id = if let Some(r) = repo {
            r.record_tool_start(job_id, tool_name, target, &command_args_str)
                .await
                .ok()
        } else {
            None
        };

        let start_time = Instant::now();

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

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(err) => {
                let duration_ms = start_time.elapsed().as_millis() as u64;
                if let (Some(r), Some(id)) = (repo, &run_id) {
                    let _ = r
                        .record_tool_finish(id, None, "FAILED", Some(&err.to_string()))
                        .await;
                }

                if err.kind() == std::io::ErrorKind::NotFound {
                    return Err(BountyScopeError::MissingBinary(binary.to_string()));
                } else {
                    return Err(BountyScopeError::Io(err));
                }
            }
        };

        // Pipe stdin if provided
        if let Some(input) = input_data {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(input.as_bytes()).await;
                let _ = stdin.shutdown().await;
            }
        }

        // Wait with timeout and cancellation support
        let wait_result = if let Some(token) = cancel_token {
            tokio::select! {
                _ = token.cancelled() => {
                    warn!("Tool '{}' was cancelled by cancellation signal. Terminating process.", tool_name);
                    if let (Some(r), Some(id)) = (repo, &run_id) {
                        let _ = r.record_tool_finish(id, None, "CANCELLED", Some("Cancelled by user/shutdown signal")).await;
                    }
                    return Err(BountyScopeError::Internal(format!("Tool '{}' was cancelled", tool_name)));
                }
                res = tokio::time::timeout(timeout_duration, child.wait_with_output()) => res,
            }
        } else {
            tokio::time::timeout(timeout_duration, child.wait_with_output()).await
        };


        let duration_ms = start_time.elapsed().as_millis() as u64;

        match wait_result {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let exit_code = output.status.code();

                let raw_lines: Vec<String> = stdout
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect();

                let status = if output.status.success() {
                    "SUCCESS"
                } else {
                    "FAILED"
                };

                if let (Some(r), Some(id)) = (repo, &run_id) {
                    let err_msg = if !output.status.success() && !stderr.is_empty() {
                        Some(stderr.as_str())
                    } else {
                        None
                    };
                    let _ = r.record_tool_finish(id, exit_code, status, err_msg).await;
                }

                Ok(ToolOutput {
                    tool_name: tool_name.to_string(),
                    target: target.to_string(),
                    stdout,
                    stderr,
                    exit_code,
                    duration_ms,
                    raw_lines,
                })
            }
            Ok(Err(io_err)) => {
                error!("I/O error during execution of '{}': {}", tool_name, io_err);
                if let (Some(r), Some(id)) = (repo, &run_id) {
                    let _ = r
                        .record_tool_finish(id, None, "FAILED", Some(&io_err.to_string()))
                        .await;
                }
                Err(BountyScopeError::Io(io_err))
            }
            Err(_) => {
                warn!(
                    "Tool '{}' timed out after {:?}. Terminating process.",
                    tool_name, timeout_duration
                );
                if let (Some(r), Some(id)) = (repo, &run_id) {
                    let _ = r
                        .record_tool_finish(
                            id,
                            None,
                            "TIMEOUT",
                            Some(&format!("Exceeded timeout of {:?}", timeout_duration)),
                        )
                        .await;
                }
                Err(BountyScopeError::ProcessTimeout {
                    binary: binary.to_string(),
                    timeout_secs: timeout_duration.as_secs(),
                })
            }
        }
    }
}
