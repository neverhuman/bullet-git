use super::transport::TransportConfig;
use crate::authority_gateway::GatewayError;
use crate::mutation_ledger::MutationSubject;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(super) const PROTO: &str = "bullet-farm.kernel-authority.rpc.v1";
const REQUEST_ID: u64 = 1;
const LINE_MAX: usize = 65_536;

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RpcRequest<'a, T> {
    proto: &'static str,
    id: u64,
    method: &'a str,
    params: &'a T,
    now_unix_ms: u64,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RpcReply<R> {
    Success(SuccessReply<R>),
    Error(ErrorReply),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuccessReply<R> {
    proto: String,
    id: u64,
    result: R,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorReply {
    proto: String,
    id: u64,
    error: RpcError,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcError {
    code: String,
    message: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CheckBody {
    pub(super) operation: String,
    pub(super) authority: Value,
    pub(super) params: Value,
    pub(super) kernel_permit: Value,
    pub(super) transport_fingerprint: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CheckReply {
    pub(super) subject: MutationSubject,
    pub(super) operation: String,
    pub(super) transport_fingerprint: String,
    pub(super) expires_at_unix_ms: u64,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SettleBody {
    pub(super) subject: MutationSubject,
    pub(super) outcome: String,
    pub(super) result_digest: String,
    pub(super) completed_at_unix_ms: u64,
    pub(super) settlement_fingerprint: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SettleReply {
    pub(super) mutation_id: String,
    pub(super) reservation_id: String,
    pub(super) result_digest: String,
    pub(super) settlement_fingerprint: String,
}

pub(super) fn call<T: Serialize, R: for<'de> Deserialize<'de>>(
    transport: &TransportConfig,
    method: &str,
    params: &T,
) -> Result<R, GatewayError> {
    let mut stream = transport.connect()?;
    let request = RpcRequest {
        proto: PROTO,
        id: REQUEST_ID,
        method,
        params,
        now_unix_ms: now_unix_ms()?,
    };
    write_line(&mut stream, &request, transport.deadline())?;
    let reply: RpcReply<R> = read_json(&mut stream, transport.deadline())?;
    match reply {
        RpcReply::Success(reply) => {
            validate_reply_identity(&reply.proto, reply.id)?;
            Ok(reply.result)
        }
        RpcReply::Error(reply) => {
            validate_reply_identity(&reply.proto, reply.id)?;
            if reply.error.code == "AUTHORITY_CONTRACT_UNAVAILABLE" {
                Err(GatewayError::ContractUnavailable(reply.error.message))
            } else {
                Err(GatewayError::Refused(format!(
                    "{}: {}",
                    reply.error.code, reply.error.message
                )))
            }
        }
    }
}

fn validate_reply_identity(proto: &str, id: u64) -> Result<(), GatewayError> {
    if proto != PROTO {
        return refused("Kernel authority response protocol mismatch");
    }
    if id != REQUEST_ID {
        return refused("Kernel authority response id mismatch");
    }
    Ok(())
}

fn write_line(
    stream: &mut UnixStream,
    value: &impl Serialize,
    timeout: Duration,
) -> Result<(), GatewayError> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| GatewayError::Refused(format!("Kernel authority encode: {error}")))?;
    bytes.push(b'\n');
    if bytes.len() > LINE_MAX {
        return refused("Kernel authority request line too long");
    }
    let deadline = deadline(timeout)?;
    let mut written = 0;
    while written < bytes.len() {
        set_write_deadline(stream, deadline)?;
        match stream.write(&bytes[written..]) {
            Ok(0) => return refused("Kernel authority write returned zero bytes"),
            Ok(count) => written += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if timed_out(&error) => {
                return refused("Kernel authority write deadline exceeded")
            }
            Err(error) => {
                return Err(GatewayError::Refused(format!(
                    "Kernel authority write failed: {error}"
                )))
            }
        }
    }
    Ok(())
}

fn read_json<R: for<'de> Deserialize<'de>>(
    stream: &mut UnixStream,
    timeout: Duration,
) -> Result<R, GatewayError> {
    let deadline = deadline(timeout)?;
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if buf.len() >= LINE_MAX {
            return refused("Kernel authority response line too long");
        }
        set_read_deadline(stream, deadline)?;
        match stream.read(&mut byte) {
            Ok(0) => return refused("Kernel authority response ended before newline"),
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => buf.push(byte[0]),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if timed_out(&error) => {
                return refused("Kernel authority read deadline exceeded")
            }
            Err(error) => {
                return Err(GatewayError::Refused(format!(
                    "Kernel authority read failed: {error}"
                )))
            }
        }
    }
    serde_json::from_slice(&buf)
        .map_err(|error| GatewayError::Refused(format!("Kernel authority decode: {error}")))
}

fn set_write_deadline(stream: &UnixStream, deadline: Instant) -> Result<(), GatewayError> {
    let remaining = remaining(deadline, "write")?;
    stream
        .set_write_timeout(Some(remaining))
        .map_err(|error| GatewayError::Refused(format!("Kernel authority write deadline: {error}")))
}

fn set_read_deadline(stream: &UnixStream, deadline: Instant) -> Result<(), GatewayError> {
    let remaining = remaining(deadline, "read")?;
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|error| GatewayError::Refused(format!("Kernel authority read deadline: {error}")))
}

fn deadline(timeout: Duration) -> Result<Instant, GatewayError> {
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| GatewayError::Refused("Kernel authority deadline overflow".into()))
}

fn remaining(deadline: Instant, operation: &str) -> Result<Duration, GatewayError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return refused(&format!("Kernel authority {operation} deadline exceeded"));
    }
    Ok(remaining)
}

fn timed_out(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock)
}

fn now_unix_ms() -> Result<u64, GatewayError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| GatewayError::Clock(error.to_string()))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| GatewayError::Clock("system time exceeds u64 milliseconds".into()))
}

fn refused<T>(message: &str) -> Result<T, GatewayError> {
    Err(GatewayError::Refused(message.into()))
}
