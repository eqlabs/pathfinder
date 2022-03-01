//! A general utility for retrying futures with a configurable backoff and error filter.
use std::{
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    result::Result,
    time::Duration,
};
use tokio_retry::{strategy::ExponentialBackoff, Retry as TokioRetry, RetryIf as TokioRetryIf};

pub struct Retry<T, E, Fut, FutureFactory>
where
    Fut: Future<Output = Result<T, E>>,
    FutureFactory: FnMut() -> Fut,
{
    future_factory: FutureFactory,
    strategy: Strategy,
}

impl<T, E, Fut, FutureFactory> Retry<T, E, Fut, FutureFactory>
where
    Fut: Future<Output = Result<T, E>>,
    FutureFactory: FnMut() -> Fut,
{
    /// Create an exponential [`Retry`] utility for a future which is created by `future_factory`
    /// with initial backoff of `base_secs` seconds.
    ///
    /// `Nth` backoff is equal to `base_secs ^ N` seconds.
    pub fn exponential(future_factory: FutureFactory, base_secs: NonZeroU64) -> Self {
        Self {
            future_factory,
            strategy: Strategy {
                base_secs,
                factor: NonZeroU64::new(1).unwrap(),
                max_delay: None,
                max_num_retries: None,
            },
        }
    }

    /// Multiply backoff by this factor.
    ///
    /// `Nth` backoff is then equal to `base_secs ^ N * factor` seconds.
    pub fn factor(mut self, factor: NonZeroU64) -> Self {
        self.strategy.factor = factor;
        self
    }

    /// Saturate backoff at `max_delay`.
    pub fn max_delay(mut self, max_delay: Duration) -> Self {
        self.strategy.max_delay = Some(max_delay);
        self
    }

    /// Limit the number of retries to `max_num_retries`.
    pub fn max_num_retries(mut self, max_num_retries: NonZeroUsize) -> Self {
        self.strategy.max_num_retries = Some(max_num_retries);
        self
    }

    /// Retry the future on any `Err()` until an `Ok()` value is returned by the future.
    pub async fn on_any_err(self) -> Result<T, E> {
        TokioRetry::spawn(MaybeLimited::from(self.strategy), self.future_factory).await
    }

    /// Retry the future on every error that meets `retry_condition` until the future returns:
    /// - an `Ok()` value
    /// - an `Err()` value that does not meet the `retry_condition`.
    pub async fn when<RetryCondition>(self, retry_condition: RetryCondition) -> Result<T, E>
    where
        RetryCondition: FnMut(&E) -> bool,
    {
        TokioRetryIf::spawn(
            MaybeLimited::from(self.strategy),
            self.future_factory,
            retry_condition,
        )
        .await
    }
}

struct Strategy {
    base_secs: NonZeroU64,
    factor: NonZeroU64,
    max_delay: Option<Duration>,
    max_num_retries: Option<NonZeroUsize>,
}

enum MaybeLimited {
    Limited(std::iter::Take<ExponentialBackoff>),
    Unlimited(ExponentialBackoff),
}

impl std::iter::Iterator for MaybeLimited {
    type Item = std::time::Duration;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            MaybeLimited::Limited(x) => x.next(),
            MaybeLimited::Unlimited(x) => x.next(),
        }
    }
}

impl From<Strategy> for MaybeLimited {
    fn from(s: Strategy) -> Self {
        // We use milliseconds in tests
        #[cfg(test)]
        const FACTOR: u32 = 1;

        // We use seconds in production
        #[cfg(not(test))]
        const FACTOR: u32 = 1000;

        let backoff = ExponentialBackoff::from_millis(s.base_secs.get()).factor(
            s.factor
                .get()
                .checked_mul(FACTOR as u64)
                .unwrap_or(u64::MAX),
        );
        let backoff = match s.max_delay {
            Some(max_delay) => {
                backoff.max_delay(max_delay.checked_mul(FACTOR).unwrap_or(Duration::MAX))
            }
            None => backoff,
        };

        match s.max_num_retries {
            Some(num_retries) => MaybeLimited::Limited(backoff.take(num_retries.get())),
            None => MaybeLimited::Unlimited(backoff),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Retry;
    use std::{
        cell::RefCell,
        iter::{IntoIterator, Iterator},
        num::{NonZeroU64, NonZeroUsize},
        result::Result,
        time::{Duration, Instant},
    };

    #[derive(Copy, Clone, Debug, PartialEq)]
    enum Failure {
        Retryable,
        Fatal,
    }

    #[derive(Copy, Clone, Debug)]
    struct Success;

    struct Uut<I>
    where
        I: IntoIterator<Item = Result<Success, Failure>>,
    {
        seq: RefCell<I::IntoIter>,
        call_count: RefCell<usize>,
        now: RefCell<Instant>,
        last: RefCell<Duration>,
    }

    impl<I> Uut<I>
    where
        I: IntoIterator<Item = Result<Success, Failure>> + Clone,
    {
        fn new(i: I) -> Self {
            Self {
                seq: RefCell::new(i.into_iter()),
                call_count: RefCell::new(0),
                now: RefCell::new(Instant::now()),
                last: RefCell::new(Duration::default()),
            }
        }

        pub async fn do_work(&self) -> Result<Success, Failure> {
            *self.call_count.borrow_mut() += 1;
            *self.last.borrow_mut() = self.now.borrow_mut().elapsed();
            *self.now.borrow_mut() = Instant::now();
            self.seq.borrow_mut().next().unwrap()
        }

        fn call_count(&self) -> usize {
            let call_counter = *self.call_count.borrow();
            call_counter
        }

        pub fn expect_last_delay(&self, expected: u64) -> Result<u64, u64> {
            let real = self.last.borrow().as_millis() as u64;
            if real > expected - expected / 8 && real < expected + expected / 8 {
                Ok(real)
            } else {
                Err(real)
            }
        }
    }

    mod unconditional {
        use super::*;

        #[tokio::test]
        async fn until_ok() {
            let uut = Uut::new([
                Err(Failure::Retryable),
                Err(Failure::Fatal),
                Err(Failure::Fatal),
                Ok(Success),
            ]);
            Retry::exponential(|| uut.do_work(), NonZeroU64::new(2).unwrap())
                .factor(NonZeroU64::new(10).unwrap())
                .on_any_err()
                .await
                .unwrap();
            assert_eq!(uut.call_count(), 4);
            // ~80ms (2^3*10)
            uut.expect_last_delay(80).unwrap();
        }

        #[tokio::test]
        async fn until_fatal() {
            let uut = Uut::new([
                Err(Failure::Retryable),
                Err(Failure::Retryable),
                Err(Failure::Retryable),
                Err(Failure::Fatal),
                Ok(Success),
            ]);
            assert_eq!(
                Retry::exponential(|| uut.do_work(), NonZeroU64::new(2).unwrap())
                    .factor(NonZeroU64::new(10).unwrap())
                    .when(|e| *e == Failure::Retryable)
                    .await
                    .unwrap_err(),
                Failure::Fatal
            );
            assert_eq!(uut.call_count(), 4);
            // ~80ms (2^3*10)
            uut.expect_last_delay(80).unwrap();
        }

        #[tokio::test]
        async fn saturate_delay() {
            let uut = Uut::new([Err(Failure::Fatal); 10]);
            Retry::exponential(|| uut.do_work(), NonZeroU64::new(2).unwrap())
                .max_delay(Duration::from_millis(128))
                .max_num_retries(NonZeroUsize::new(9).unwrap())
                .on_any_err()
                .await
                .unwrap_err();
            assert_eq!(uut.call_count(), 10);
            // If not capped, would be ~512ms (2^9*1)
            uut.expect_last_delay(128).unwrap();
        }

        #[tokio::test]
        async fn reach_max_num_retries() {
            let uut = Uut::new([
                Err(Failure::Retryable),
                Err(Failure::Retryable),
                Err(Failure::Retryable),
                Err(Failure::Fatal),
                Ok(Success),
            ]);
            assert_eq!(
                Retry::exponential(|| uut.do_work(), NonZeroU64::new(1).unwrap())
                    .max_num_retries(NonZeroUsize::new(3).unwrap())
                    .on_any_err()
                    .await
                    .unwrap_err(),
                Failure::Fatal
            );
            // Retry limit of 3 means 4 tries altogether
            assert_eq!(uut.call_count(), 4);
        }
    }

    mod conditional {
        use super::*;

        #[tokio::test]
        async fn until_fatal() {
            let uut = Uut::new([
                Err(Failure::Retryable),
                Err(Failure::Retryable),
                Err(Failure::Retryable),
                Err(Failure::Fatal),
                Ok(Success),
            ]);
            assert_eq!(
                Retry::exponential(|| uut.do_work(), NonZeroU64::new(2).unwrap())
                    .factor(NonZeroU64::new(10).unwrap())
                    .when(|e| *e == Failure::Retryable)
                    .await
                    .unwrap_err(),
                Failure::Fatal
            );
            assert_eq!(uut.call_count(), 4);
            // ~80ms (2^3*10)
            uut.expect_last_delay(80).unwrap();
        }

        #[tokio::test]
        async fn until_ok() {
            let uut = Uut::new([
                Err(Failure::Retryable),
                Err(Failure::Retryable),
                Err(Failure::Retryable),
                Ok(Success),
                Err(Failure::Fatal),
            ]);
            Retry::exponential(|| uut.do_work(), NonZeroU64::new(2).unwrap())
                .factor(NonZeroU64::new(10).unwrap())
                .when(|e| *e == Failure::Retryable)
                .await
                .unwrap();
            // ~80ms (2^3*10)
            assert_eq!(uut.call_count(), 4);
            uut.expect_last_delay(80).unwrap();
        }

        #[tokio::test]
        async fn saturate_delay() {
            let uut = Uut::new([Err(Failure::Retryable); 10]);
            Retry::exponential(|| uut.do_work(), NonZeroU64::new(2).unwrap())
                .max_delay(Duration::from_millis(128))
                .max_num_retries(NonZeroUsize::new(9).unwrap())
                .when(|e| *e == Failure::Retryable)
                .await
                .unwrap_err();
            assert_eq!(uut.call_count(), 10);
            uut.expect_last_delay(128).unwrap();
        }

        #[tokio::test]
        async fn reach_max_num_retries() {
            let uut = Uut::new([
                Err(Failure::Retryable),
                Err(Failure::Retryable),
                Err(Failure::Retryable),
                Err(Failure::Fatal),
            ]);
            assert_eq!(
                Retry::exponential(|| uut.do_work(), NonZeroU64::new(1).unwrap())
                    .max_num_retries(NonZeroUsize::new(2).unwrap())
                    .when(|e| *e == Failure::Retryable)
                    .await
                    .unwrap_err(),
                Failure::Retryable
            );
            // Retry limit of 2 means 3 tries altogether
            assert_eq!(uut.call_count(), 3);
        }
    }
}
