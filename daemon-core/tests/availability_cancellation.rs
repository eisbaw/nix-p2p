//! A metadata-query deadline must reach the actual supervised dump process.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use daemon_core::availability::{CancellationCheck, NullAnnounce, NullStore};
use daemon_core::{AvailabilityIndex, CommandNarDumper, NarHashKey, NodeId, StorePath};

struct Deadline(Instant);
impl CancellationCheck for Deadline {
    fn is_cancelled(&self) -> bool {
        Instant::now() >= self.0
    }
}

#[test]
fn metadata_verification_deadline_kills_and_reaps_the_dump() {
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let dir = Scratch(std::env::temp_dir().join(format!("nix-p2p-cancel-{}", std::process::id())));
    std::fs::create_dir(&dir.0).unwrap();
    let shell = std::process::Command::new("sh")
        .args(["-c", "command -v sh"])
        .output()
        .unwrap();
    assert!(shell.status.success());
    let shell = String::from_utf8(shell.stdout).unwrap();
    let script = dir.0.join("dump");
    let pid_file = dir.0.join("pid");
    std::fs::write(
        &script,
        format!(
            "#!{}\necho $$ > '{}'\nexec sleep 30\n",
            shell.trim(),
            pid_file.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.0.join("store-output");
    std::fs::write(&path, b"exists").unwrap();
    let index = AvailabilityIndex::open(
        NodeId::from_bytes([1; 32]),
        Arc::new(CommandNarDumper::with_program(&script)),
        Arc::new(NullStore),
        Arc::new(NullAnnounce),
    )
    .unwrap();
    let hash = NarHashKey::from_raw_nar(b"not-produced");
    index.register(hash, StorePath::new(path)).unwrap();
    let start = Instant::now();
    let result = index.hold_cancellable(&hash, &Deadline(start + Duration::from_secs(2)));
    assert!(result.unwrap_err().to_string().contains("cancelled"));
    assert!(start.elapsed() < Duration::from_secs(5));
    let pid = std::fs::read_to_string(pid_file).unwrap();
    assert!(
        !std::path::Path::new(&format!("/proc/{}", pid.trim())).exists(),
        "dump process was not reaped"
    );
    assert!(
        index
            .supply_catalog()
            .probe_record(&peer_fabric::Blake3Digest::from_raw_nar(b"not-produced"))
            .is_none()
    );
}
