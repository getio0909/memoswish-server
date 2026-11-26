//! 安装写入进程持有目录 inode 的排他 flock，与冷备份使用同一锁对象。

use std::{
    fs::File,
    path::Path,
    sync::{Mutex, OnceLock},
};

use anyhow::Context;

// 静态描述符由内核在进程退出时释放，运行时遗留的阻塞磁盘任务也不能提前失去锁。
static WRITER_LOCK: OnceLock<File> = OnceLock::new();
// 同进程并发启动须在创建另一安装目录之前观察到已取得的静态锁。
static STARTUP: Mutex<()> = Mutex::new(());

pub fn acquire(directory: &Path) -> anyhow::Result<()> {
    acquire_with(directory, true)
}

// 只读维护要求已有安装目录，锁冲突或目录缺失均不得初始化安装。
pub(crate) fn acquire_existing(directory: &Path) -> anyhow::Result<()> {
    acquire_with(directory, false)
}

fn acquire_with(directory: &Path, create: bool) -> anyhow::Result<()> {
    let _startup = STARTUP.lock().map_err(|_| anyhow::anyhow!("data directory lock initialization failed"))?;
    anyhow::ensure!(WRITER_LOCK.get().is_none(), "data directory lock is already initialized");
    if create {
        std::fs::create_dir_all(directory).context("cannot create data directory")?;
    }
    // Linux 本地目录本身不可作为可删除锁文件；不创建或替换单独的锁路径。
    #[cfg(unix)]
    let file = File::open(directory).context("cannot open data directory for locking")?;
    // 非 Unix 平台保留原服务启动能力，永久锁文件不得删除；冷恢复工具仍仅支持 Linux。
    #[cfg(not(unix))]
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join(".learntok-writer.lock"))
        .context("cannot open data directory lock")?;
    fs4::FileExt::try_lock(&file).context("data directory is locked by another writer or recovery operation")?;
    WRITER_LOCK.set(file).map_err(|_| anyhow::anyhow!("data directory lock is already initialized"))
}
