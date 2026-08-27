use super::super::transport::{
    validate_connected_identity, ExpectedServer, SocketIdentity, TransportConfig,
};
use std::ffi::OsString;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::time::Duration;

fn id(value: u32) -> Option<OsString> {
    Some(OsString::from(value.to_string()))
}

#[test]
fn configuration_and_socket_identity_are_explicit_and_exact() {
    let timeout = Duration::from_millis(100);
    assert!(TransportConfig::from_values(None, id(1), id(1), timeout).is_err());
    assert!(TransportConfig::from_values(
        Some("relative.sock".into()),
        Some(OsString::from("bad")),
        id(1),
        timeout,
    )
    .is_err());
    let relative =
        TransportConfig::from_values(Some("relative.sock".into()), id(1), id(1), timeout)
            .expect("numeric identity config");
    assert!(relative.connect().is_err());
    assert!(
        TransportConfig::from_values(Some("relative.sock".into()), id(1), None, timeout,).is_err()
    );
    assert!(TransportConfig::from_values(
        Some("relative.sock".into()),
        id(1),
        id(1),
        Duration::ZERO,
    )
    .is_err());

    let root = tempfile::tempdir().expect("tempdir");
    let socket = root.path().join("authority.sock");
    let listener = UnixListener::bind(&socket).expect("bind");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).expect("mode");
    let meta = std::fs::metadata(&socket).expect("metadata");

    let wrong_uid = TransportConfig::from_values(
        Some(socket.clone()),
        id(meta.uid().wrapping_add(1)),
        id(meta.gid()),
        timeout,
    )
    .expect("config");
    assert!(wrong_uid.connect().is_err());

    let wrong_gid = TransportConfig::from_values(
        Some(socket.clone()),
        id(meta.uid()),
        id(meta.gid().wrapping_add(1)),
        timeout,
    )
    .expect("config");
    assert!(wrong_gid.connect().is_err());

    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).expect("mode");
    let expected = TransportConfig::from_values(
        Some(socket.clone()),
        id(meta.uid()),
        id(meta.gid()),
        timeout,
    )
    .expect("config");
    assert!(expected.connect().is_err());
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).expect("mode");

    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o1660)).expect("mode");
    assert!(expected.connect().is_err());
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).expect("mode");

    let link = root.path().join("authority-link.sock");
    std::os::unix::fs::symlink(&socket, &link).expect("symlink");
    let linked = TransportConfig::from_values(Some(link), id(meta.uid()), id(meta.gid()), timeout)
        .expect("config");
    assert!(linked.connect().is_err());

    let linked_parent = root.path().join("linked-parent");
    std::os::unix::fs::symlink(root.path(), &linked_parent).expect("parent symlink");
    let through_parent = TransportConfig::from_values(
        Some(linked_parent.join("authority.sock")),
        id(meta.uid()),
        id(meta.gid()),
        timeout,
    )
    .expect("config");
    assert!(through_parent.connect().is_err());

    let accept = std::thread::spawn(move || listener.accept().expect("accept").0);
    let stream = expected.connect().expect("exact identity");
    drop(stream);
    drop(accept.join().expect("server"));

    let expected_server = ExpectedServer {
        uid: meta.uid(),
        socket_gid: meta.gid(),
    };
    let identity = SocketIdentity {
        dev: 1,
        ino: 2,
        uid: meta.uid(),
        gid: meta.gid(),
        mode: 0o660,
    };
    validate_connected_identity(expected_server, identity, identity, meta.uid())
        .expect("stable connected identity");
    for changed in [
        SocketIdentity { dev: 3, ..identity },
        SocketIdentity { ino: 3, ..identity },
        SocketIdentity {
            uid: meta.uid().wrapping_add(1),
            ..identity
        },
        SocketIdentity {
            gid: meta.gid().wrapping_add(1),
            ..identity
        },
        SocketIdentity {
            mode: 0o600,
            ..identity
        },
    ] {
        assert!(
            validate_connected_identity(expected_server, identity, changed, meta.uid()).is_err()
        );
    }
    assert!(validate_connected_identity(
        expected_server,
        identity,
        identity,
        meta.uid().wrapping_add(1),
    )
    .is_err());
}
