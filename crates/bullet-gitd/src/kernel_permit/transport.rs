use crate::authority_gateway::GatewayError;
use std::ffi::OsString;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const SOCKET_MODE: u32 = 0o660;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SocketIdentity {
    pub(super) dev: u64,
    pub(super) ino: u64,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) mode: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ExpectedServer {
    pub(super) uid: u32,
    pub(super) socket_gid: u32,
}

pub(super) struct TransportConfig {
    socket: PathBuf,
    expected: ExpectedServer,
    deadline: Duration,
}

impl TransportConfig {
    pub(super) fn from_values(
        socket: Option<PathBuf>,
        uid: Option<OsString>,
        socket_gid: Option<OsString>,
        deadline: Duration,
    ) -> Result<Self, String> {
        let socket = socket.ok_or("BULLET_KERNEL_AUTHORITY_SOCKET is missing")?;
        let uid = parse_id("BULLET_KERNEL_AUTHORITY_SERVER_UID", uid)?;
        let socket_gid = parse_id("BULLET_KERNEL_AUTHORITY_SOCKET_GID", socket_gid)?;
        if deadline.is_zero() {
            return Err("Kernel authority deadline must be positive".into());
        }
        Ok(Self {
            socket,
            expected: ExpectedServer { uid, socket_gid },
            deadline,
        })
    }

    pub(super) fn deadline(&self) -> Duration {
        self.deadline
    }

    pub(super) fn connect(&self) -> Result<UnixStream, GatewayError> {
        let before = self.admit_socket()?;
        let stream = connect_with_deadline(&self.socket, self.deadline)?;
        let peer_uid = peer_uid(&stream)?;
        let after = self.admit_socket()?;
        validate_connected_identity(self.expected, before, after, peer_uid)?;
        Ok(stream)
    }

    fn admit_socket(&self) -> Result<SocketIdentity, GatewayError> {
        let path = &self.socket;
        if !path.is_absolute() {
            return refused("Kernel authority socket must be an absolute path");
        }
        let parent = path
            .parent()
            .ok_or_else(|| GatewayError::Refused("Kernel authority socket has no parent".into()))?;
        let canonical_parent = std::fs::canonicalize(parent).map_err(|error| {
            GatewayError::Refused(format!("Kernel authority socket parent: {error}"))
        })?;
        if canonical_parent != parent {
            return refused(
                "Kernel authority socket parent must be canonical with no symlink traversal",
            );
        }
        let meta = std::fs::symlink_metadata(path).map_err(|error| {
            GatewayError::Refused(format!("Kernel authority socket metadata: {error}"))
        })?;
        if meta.file_type().is_symlink() || !meta.file_type().is_socket() {
            return refused("Kernel authority path must be a non-symlink Unix socket");
        }
        let identity = SocketIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.permissions().mode() & 0o7777,
        };
        if identity.mode != SOCKET_MODE {
            return refused("Kernel authority socket must be mode 0660");
        }
        if identity.uid != self.expected.uid {
            return refused(
                "Kernel authority socket owner does not match the admitted service UID",
            );
        }
        if identity.gid != self.expected.socket_gid {
            return refused("Kernel authority socket group does not match the admitted socket GID");
        }
        Ok(identity)
    }
}

fn parse_id(name: &str, value: Option<OsString>) -> Result<u32, String> {
    let value = value.ok_or_else(|| format!("{name} is missing"))?;
    let value = value
        .into_string()
        .map_err(|_| format!("{name} is not UTF-8"))?;
    value
        .parse::<u32>()
        .map_err(|_| format!("{name} must be an unsigned 32-bit integer"))
}

fn connect_with_deadline(path: &Path, deadline: Duration) -> Result<UnixStream, GatewayError> {
    use rustix::event::{poll, PollFd, PollFlags};
    use rustix::net::{
        connect, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType,
    };

    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|error| GatewayError::Refused(format!("Kernel authority socket: {error}")))?;
    let address = SocketAddrUnix::new(path)
        .map_err(|error| GatewayError::Refused(format!("Kernel authority address: {error}")))?;
    match connect(&socket, &address) {
        Ok(()) => {}
        Err(error)
            if error == rustix::io::Errno::INPROGRESS || error == rustix::io::Errno::AGAIN =>
        {
            let expires = Instant::now().checked_add(deadline).ok_or_else(|| {
                GatewayError::Refused("Kernel authority deadline overflow".into())
            })?;
            loop {
                let remaining = expires.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return refused("Kernel authority connect deadline exceeded");
                }
                let timeout = rustix::event::Timespec::try_from(remaining).map_err(|_| {
                    GatewayError::Refused("Kernel authority connect deadline is invalid".into())
                })?;
                let mut fds = [PollFd::new(&socket, PollFlags::OUT)];
                match poll(&mut fds, Some(&timeout)) {
                    Ok(0) => return refused("Kernel authority connect deadline exceeded"),
                    Ok(_) => {
                        let ready = fds[0].revents();
                        if ready.intersects(PollFlags::NVAL | PollFlags::HUP) {
                            return refused("Kernel authority connect failed");
                        }
                        break;
                    }
                    Err(error) if error == rustix::io::Errno::INTR => continue,
                    Err(error) => {
                        return Err(GatewayError::Refused(format!(
                            "Kernel authority connect poll failed: {error}"
                        )))
                    }
                }
            }
            match rustix::net::sockopt::socket_error(&socket) {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    return Err(GatewayError::Refused(format!(
                        "Kernel authority connect failed: {error}"
                    )))
                }
                Err(error) => {
                    return Err(GatewayError::Refused(format!(
                        "Kernel authority connect status failed: {error}"
                    )))
                }
            }
        }
        Err(error) => {
            return Err(GatewayError::Refused(format!(
                "Kernel authority connect failed: {error}"
            )))
        }
    }
    let stream = UnixStream::from(socket);
    stream.set_nonblocking(false).map_err(|error| {
        GatewayError::Refused(format!("Kernel authority blocking mode: {error}"))
    })?;
    Ok(stream)
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Result<u32, GatewayError> {
    rustix::net::sockopt::socket_peercred(stream)
        .map(|peer| peer.uid.as_raw())
        .map_err(|error| GatewayError::Refused(format!("Kernel authority SO_PEERCRED: {error}")))
}

#[cfg(not(target_os = "linux"))]
fn peer_uid(_stream: &UnixStream) -> Result<u32, GatewayError> {
    refused("Kernel authority server identity requires Linux SO_PEERCRED")
}

pub(super) fn validate_connected_identity(
    expected: ExpectedServer,
    before: SocketIdentity,
    after: SocketIdentity,
    peer_uid: u32,
) -> Result<(), GatewayError> {
    if before != after {
        return refused("Kernel authority socket identity changed during connect");
    }
    if peer_uid != expected.uid {
        return refused("Kernel authority peer UID does not match the admitted service UID");
    }
    Ok(())
}

fn refused<T>(message: &str) -> Result<T, GatewayError> {
    Err(GatewayError::Refused(message.into()))
}
