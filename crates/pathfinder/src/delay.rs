use std::sync::{Arc, RwLock};

pub trait Delay {
    fn success(&self);
    fn failure(&self);
    fn get(&self) -> std::time::Duration;
}

struct Inner {
    ok: bool,
    min: std::time::Duration,
    max: std::time::Duration,
    current: std::time::Duration,
}

pub struct ExpBackoffDelay {
    inner: Arc<RwLock<Inner>>,
}

impl ExpBackoffDelay {
    pub fn new(min: std::time::Duration, max: std::time::Duration) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner {
                ok: true,
                min,
                max,
                current: max,
            }))
        }
    }
}

impl Delay for ExpBackoffDelay {
    fn success(&self) {
        let mut this = self.inner.try_write().unwrap();
        this.current = this.max;
        this.ok = true;
    }

    fn failure(&self) {
        let mut this = self.inner.try_write().unwrap();
        if this.ok {
            this.current = this.min;
        } else {
            this.current *= 2;
        }
        if this.current > this.max {
            this.current = this.max;
        }
        this.ok = false;
    }

    fn get(&self) -> std::time::Duration {
        let this = self.inner.try_read().unwrap();
        this.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff() {
        let min = std::time::Duration::from_secs(1);
        let max = std::time::Duration::from_secs(10);

        let backoff = ExpBackoffDelay::new(min, max);
        assert_eq!(backoff.get(), max);

        backoff.success();
        assert_eq!(backoff.get(), max);

        backoff.failure();
        assert_eq!(backoff.get(), min);

        backoff.failure();
        assert_eq!(backoff.get(), min * 2);

        backoff.failure();
        assert_eq!(backoff.get(), min * 4);

        backoff.failure();
        assert_eq!(backoff.get(), min * 8);

        backoff.failure();
        assert_eq!(backoff.get(), max);

        backoff.failure();
        assert_eq!(backoff.get(), max);

        backoff.success();
        assert_eq!(backoff.get(), max);
    }
}
