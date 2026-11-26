//! 密钥文件使用固定目录描述符、私有 staging 与不覆盖发布；读取失败绝不改变身份。
use std::path::Path;

pub(crate) fn read(path: &Path) -> anyhow::Result<Option<String>> {
    #[cfg(unix)]
    {
        let key = unix::read(path).map_err(|_| anyhow::anyhow!("cannot read a valid managed JWT key"))?;
        if let Some(value) = &key {
            super::validation::reject_placeholder("jwt_secret", value)?;
        }
        Ok(key)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        anyhow::bail!("managed key files are unsupported on this platform; inject jwt_secret through protected config")
    }
}

pub(crate) fn resolve(path: &Path) -> anyhow::Result<String> {
    if let Some(key) = read(path)? {
        return Ok(key);
    }
    #[cfg(unix)]
    let key = memoswish_auth::token::generate_secret();
    let parent = path.parent().ok_or_else(|| anyhow::anyhow!("invalid managed key path"))?;
    std::fs::create_dir_all(parent).map_err(|_| anyhow::anyhow!("cannot create key directory"))?;
    #[cfg(unix)]
    match unix::publish(path, key.as_bytes()) {
        Ok(()) => Ok(key),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            read(path)?.ok_or_else(|| anyhow::anyhow!("competing key publication disappeared"))
        }
        Err(_) => anyhow::bail!("cannot publish managed JWT key"),
    }
    #[cfg(not(unix))]
    anyhow::bail!("managed key creation is unsupported on this platform")
}

/// 输出只在完整写入并同步后可见，任何既有文件或链接都不能覆盖。
pub(crate) fn publish(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        unix::publish(path, bytes).map_err(|_| anyhow::anyhow!("cannot publish private output file"))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, bytes);
        anyhow::bail!("private output creation is unsupported on this platform")
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use rustix::fs::{AtFlags, Mode, OFlags, linkat, open, openat, unlinkat};
    use std::{
        fs::File,
        io::{Read, Write},
        os::unix::fs::MetadataExt,
    };

    fn directory(path: &Path) -> std::io::Result<File> {
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        Ok(open(parent, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW, Mode::empty())?.into())
    }

    pub(super) fn read(path: &Path) -> std::io::Result<Option<String>> {
        let dir = match directory(path) {
            Ok(dir) => dir,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let name = path.file_name().ok_or(std::io::ErrorKind::InvalidInput)?;
        let fd = match openat(
            &dir,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let file = File::from(fd);
        let meta = file.metadata()?;
        if !meta.is_file() || meta.len() > 65536 || meta.mode() & 0o077 != 0 || meta.mode() & 0o400 == 0 {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        let mut key = String::new();
        file.take(65537).read_to_string(&mut key)?;
        let key = key.trim();
        if key.len() < 32 || key.len() > 65536 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        Ok(Some(key.into()))
    }

    pub(super) fn publish(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        publish_with(path, bytes, |_| Ok(()))
    }

    pub(super) fn publish_with(
        path: &Path,
        bytes: &[u8],
        hook: impl Fn(&str) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        let dir = directory(path)?;
        let name = path.file_name().ok_or(std::io::ErrorKind::InvalidInput)?;
        let stage = format!(".learntok-key-{}", memoswish_core::ids::new_id());
        let fd = openat(
            &dir,
            stage.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )?;
        let result = (|| {
            let mut file = File::from(fd);
            hook("created")?;
            file.write_all(bytes)?;
            hook("written")?;
            file.sync_all()?;
            hook("synced")?;
            // linkat 没有覆盖语义，目标包括悬空链接时也必须失败。
            linkat(&dir, stage.as_str(), &dir, name, AtFlags::empty())?;
            hook("published")?;
            dir.sync_all()?;
            hook("directory_synced")
        })();
        let cleanup = unlinkat(&dir, stage.as_str(), AtFlags::empty()).map_err(std::io::Error::from);
        result?;
        cleanup?;
        dir.sync_all()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::{
        fs::{PermissionsExt, symlink},
        net::UnixListener,
    };
    fn root() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("s26b-key-{}", memoswish_core::ids::new_id()));
        std::fs::create_dir(&dir).unwrap();
        dir
    }
    fn private(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[test]
    fn invalid_existing_keys_are_never_replaced() {
        let dir = root();
        let key = dir.join("jwt_secret");
        for bytes in [b"short".to_vec(), vec![255; 64], b" ".repeat(40), vec![b'x'; 65537]] {
            private(&key, &bytes);
            assert!(resolve(&key).is_err());
            assert_eq!(std::fs::read(&key).unwrap(), bytes);
        }
        private(&key, &[b'x'; 32]);
        for mode in [0o000, 0o200, 0o644, 0o666] {
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(resolve(&key).is_err());
        }
        assert_eq!(std::fs::read(&key).unwrap(), vec![b'x'; 32]);
        std::fs::remove_file(&key).unwrap();
        for target in [dir.join("missing"), dir.join("existing")] {
            private(&dir.join("existing"), &[b'y'; 32]);
            symlink(&target, &key).unwrap();
            assert!(resolve(&key).is_err());
            assert!(std::fs::symlink_metadata(&key).unwrap().file_type().is_symlink());
            std::fs::remove_file(&key).unwrap();
        }
        std::fs::create_dir(&key).unwrap();
        assert!(resolve(&key).is_err());
        std::fs::remove_dir(&key).unwrap();
        let socket = UnixListener::bind(&key).unwrap();
        assert!(resolve(&key).is_err());
        drop(socket);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn concurrent_publishers_get_one_complete_private_identity() {
        let dir = root();
        let path = dir.join("jwt_secret");
        let gate = std::sync::Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let path = path.clone();
                let gate = gate.clone();
                std::thread::spawn(move || {
                    gate.wait();
                    resolve(&path).unwrap()
                })
            })
            .collect();
        let keys: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert!(keys.iter().all(|key| *key == keys[0]));
        assert_eq!(read(&path).unwrap().unwrap(), keys[0]);
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        assert!(publish(&path, b"replacement").is_err());
        assert_eq!(read(&path).unwrap().unwrap(), keys[0]);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn failed_and_linked_outputs_are_exclusive() {
        let dir = root();
        let path = dir.join("output");
        symlink(dir.join("missing"), &path).unwrap();
        assert!(publish(&path, b"secret").is_err());
        assert!(!dir.join("missing").exists());
        assert!(publish(&dir.join("missing/output"), b"secret").is_err());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(all(test, unix))]
mod fault_tests {
    use super::*;
    #[test]
    fn interrupted_publication_never_exposes_a_partial_key() {
        for phase in ["created", "written", "synced", "published", "directory_synced"] {
            let dir = std::env::temp_dir().join(format!("s26b-fault-{}", memoswish_core::ids::new_id()));
            std::fs::create_dir(&dir).unwrap();
            let path = dir.join("jwt_secret");
            assert!(
                unix::publish_with(&path, &[b'k'; 64], |at| {
                    if at == phase { Err(std::io::ErrorKind::Other.into()) } else { Ok(()) }
                })
                .is_err()
            );
            if matches!(phase, "published" | "directory_synced") {
                assert_eq!(read(&path).unwrap().unwrap(), "k".repeat(64));
            } else {
                assert!(!path.exists());
            }
            assert!(std::fs::read_dir(&dir).unwrap().all(|e| e.unwrap().file_name() == "jwt_secret"));
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}

#[cfg(all(test, unix))]
mod process_tests {
    use super::*;
    use std::{
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
    };
    struct OwnedChild(std::process::Child);
    impl std::ops::Deref for OwnedChild {
        type Target = std::process::Child;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
    impl std::ops::DerefMut for OwnedChild {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn child(case: &str, dir: &Path) -> OwnedChild {
        OwnedChild(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "config::key_file::process_tests::isolated_key_child", "--nocapture"])
                .env("MEMOSWISH_S26B_CHILD", format!("{case}|{}", dir.display()))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }
    #[test]
    fn isolated_key_child() {
        let Ok(value) = crate::test_environment::var("MEMOSWISH_S26B_CHILD") else {
            return;
        };
        let (case, root) = value.split_once('|').unwrap();
        let root = Path::new(root);
        rustix::process::umask(rustix::fs::Mode::empty());
        let key = root.join("jwt_secret");
        if case == "race" {
            let secret = resolve(&key).unwrap();
            let fingerprint = memoswish_core::ids::sha256_hex(secret.as_bytes());
            std::fs::write(root.join(format!("winner-{}", std::process::id())), fingerprint).unwrap();
            return;
        }
        unix::publish_with(&key, &[b'k'; 64], |at| {
            if at == case {
                std::fs::write(root.join("entered"), at).unwrap();
                loop {
                    std::thread::park();
                }
            }
            Ok(())
        })
        .unwrap();
    }
    #[test]
    fn kill_at_publication_boundaries_preserves_complete_identity_and_private_staging() {
        for phase in ["created", "written", "synced", "published", "directory_synced"] {
            let dir = std::env::temp_dir().join(format!("s26b-kill-{}", memoswish_core::ids::new_id()));
            std::fs::create_dir(&dir).unwrap();
            let mut process = child(phase, &dir);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !dir.join("entered").exists() {
                assert!(std::time::Instant::now() < deadline, "child never entered publication boundary");
                assert!(process.try_wait().unwrap().is_none(), "child exited early");
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            process.kill().unwrap();
            assert!(!process.wait().unwrap().success());
            let key = read(&dir.join("jwt_secret")).unwrap();
            if matches!(phase, "published" | "directory_synced") {
                assert_eq!(key.unwrap(), "k".repeat(64));
            } else {
                assert!(key.is_none());
            }
            for entry in std::fs::read_dir(&dir).unwrap().map(Result::unwrap) {
                if entry.file_name().to_string_lossy().starts_with(".learntok-key-") {
                    assert_eq!(entry.metadata().unwrap().permissions().mode() & 0o777, 0o600);
                }
            }
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
    #[test]
    fn separate_processes_with_open_umask_share_one_private_key() {
        assert!(!rustix::process::geteuid().is_root(), "permission regression requires a non-root process");
        let dir = std::env::temp_dir().join(format!("s26b-race-{}", memoswish_core::ids::new_id()));
        std::fs::create_dir(&dir).unwrap();
        let mut processes: Vec<_> = (0..4).map(|_| child("race", &dir)).collect();
        for process in &mut processes {
            assert!(process.wait().unwrap().success());
        }
        let key = dir.join("jwt_secret");
        assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
        let fingerprint = memoswish_core::ids::sha256_hex(read(&key).unwrap().unwrap().as_bytes());
        for entry in std::fs::read_dir(&dir).unwrap().map(Result::unwrap) {
            if entry.file_name().to_string_lossy().starts_with("winner-") {
                assert_eq!(std::fs::read_to_string(entry.path()).unwrap(), fingerprint);
            }
        }
        rustix::fs::mkfifoat(rustix::fs::CWD, dir.join("fifo"), rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR)
            .unwrap();
        assert!(resolve(&dir.join("fifo")).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
