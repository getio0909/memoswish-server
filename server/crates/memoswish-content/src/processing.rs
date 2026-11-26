//! 同一解析操作共享的协作期限与确定性工作额度。
use memoswish_core::{CoreError, CoreResult};
use std::cell::RefCell;
use std::io::Read;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct WorkBudget(Arc<Inner>);
struct Inner {
    deadline: Instant,
    remaining: AtomicU64,
}
thread_local! { static ACTIVE: RefCell<Option<WorkBudget>> = const { RefCell::new(None) }; }

impl Default for WorkBudget {
    fn default() -> Self {
        Self::new(512 * 1024 * 1024, Duration::from_secs(5))
    }
}
impl WorkBudget {
    pub fn new(units: u64, duration: Duration) -> Self {
        Self(Arc::new(Inner { deadline: Instant::now() + duration, remaining: AtomicU64::new(units) }))
    }
    #[allow(deprecated)]
    pub fn charge(&self, units: usize) -> CoreResult<()> {
        if Instant::now() >= self.0.deadline
            || self
                .0
                .remaining
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(units as u64))
                .is_err()
        {
            return Err(CoreError::invalid("processing budget exceeded"));
        }
        Ok(())
    }
    pub fn scope<T>(&self, operation: impl FnOnce() -> T) -> T {
        struct Restore(Option<WorkBudget>);
        impl Drop for Restore {
            fn drop(&mut self) {
                ACTIVE.with(|active| *active.borrow_mut() = self.0.take());
            }
        }
        let previous = ACTIVE.with(|active| active.replace(Some(self.clone())));
        let _restore = Restore(previous);
        operation()
    }
}

pub fn checkpoint(units: usize) -> CoreResult<()> {
    ACTIVE.with(|active| active.borrow().as_ref().map_or(Ok(()), |budget| budget.charge(units)))
}

/// 有界读取让库内的 JSON/解压读取也经过同一协作期限。
pub struct BudgetReader<R> {
    pub reader: R,
    pub budget: WorkBudget,
}
impl<R: Read> Read for BudgetReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        self.budget
            .charge(0)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "processing deadline exceeded"))?;
        let length = out.len().min(64 * 1024);
        let n = self.reader.read(&mut out[..length])?;
        self.budget.charge(n).map_err(|_| std::io::Error::other("processing work budget exceeded"))?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn processing_budget_boundary_plus_one_and_expired_reader() {
        let budget = WorkBudget::new(3, Duration::from_secs(5));
        assert!(budget.charge(3).is_ok());
        assert!(budget.charge(1).is_err());
        let mut reader = BudgetReader { reader: &b"x"[..], budget: WorkBudget::new(1, Duration::ZERO) };
        assert_eq!(reader.read(&mut [0; 1]).unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    }
    #[test]
    fn processing_scope_restores_after_nested_failure() {
        WorkBudget::new(3, Duration::from_secs(5)).scope(|| {
            WorkBudget::new(0, Duration::from_secs(5)).scope(|| assert!(checkpoint(1).is_err()));
            assert!(checkpoint(3).is_ok());
            assert!(checkpoint(1).is_err());
        });
    }
}
