//! Various test utils used in other pathfinder related crates

/// Metrics related test aids
pub mod metrics {
    use metrics::{
        Counter, CounterFn, Gauge, Histogram, Key, KeyName, Label, Recorder, SharedString, Unit,
    };
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

    // The flag means if the current recorder is a noop one
    static RECORDER_LOCK: RwLock<()> = RwLock::new(());

    enum GuardType<'a> {
        CommonNoop(RwLockReadGuard<'a, ()>),
        Exclusive(RwLockWriteGuard<'a, ()>),
    }

    /// # Purpose
    ///
    /// Allows to safely set a [`metrics::Recorder`] for a particular test.
    /// The recorder will be removed when this guard is dropped.
    /// Internal mutex protects us from inter-test recorder races.
    ///
    /// # Rationale
    ///
    /// The [`metrics`] crate relies on the recorder being a [singleton](https://docs.rs/metrics/latest/metrics/#installing-recorders).
    pub struct RecorderGuard<'a>(GuardType<'a>);

    impl<'a> RecorderGuard<'a> {
        /// # Usage
        ///
        /// Use this lock in a test if you wish to test if particular metrics were recorded properly.
        /// This is an __exclusive__ lock, which means all other tests that use the [`RecorderGuard`]
        /// will wait for this test to finish (this instance of the guard to be dropped).
        ///
        /// Locks the global RwLock for writing and sets the global `metrics::Recorder` for the current test.
        /// The global recorder is cleared and the write lock is unlocked when the guard is dropped.
        ///
        /// # Caveats
        ///
        /// The `recorder` passed to this function will be moved onto the heap and then __leaked__
        /// but we don't really care as this is purely a testing aid.
        ///
        /// # Panics
        ///
        /// If the internal locking for write or setting the global recorder fails.
        pub fn lock<R>(recorder: R) -> Self
        where
            R: Recorder + 'static,
        {
            let guard = RECORDER_LOCK.write().unwrap();

            metrics::set_boxed_recorder(Box::new(recorder)).unwrap();

            Self(GuardType::Exclusive(guard))
        }

        /// # Usage
        ///
        /// If a particular test depends on incrementing a metrics counter other tests
        /// that also could be incrementing this counter concurrently need to
        /// perform this lock to avoid interference which will result in invalid
        /// counts in the original test.
        ///
        /// The internal RwLock is locked for reading which means that all tests
        /// that `lock_as_noop()` concurrently don't wait for each other.
        ///
        /// # Panics
        ///
        /// If internal locking for read fails.
        pub fn lock_as_noop() -> Self {
            let guard = RECORDER_LOCK.read().unwrap();

            Self(GuardType::CommonNoop(guard))
        }
    }

    impl<'a> Drop for RecorderGuard<'a> {
        fn drop(&mut self) {
            match self.0 {
                GuardType::CommonNoop(_) => {}
                GuardType::Exclusive(_) => unsafe { metrics::clear_recorder() },
            }
        }
    }

    #[derive(Debug)]
    /// Mocks a [recorder](`metrics::Recorder`) only for specified [labels](`metrics::Label`)
    /// treating the rest of registered metrics as _no-op_
    pub struct FakeRecorder(FakeRecorderHandle);

    #[derive(Debug, Clone)]
    /// Handle to the [`FakeRecorder`], which allows to get the current value of counters.
    pub struct FakeRecorderHandle {
        counters: Arc<RwLock<HashMap<Key, Arc<FakeCounterFn>>>>,
        methods: &'static [&'static str],
    }

    #[derive(Debug, Default)]
    struct FakeCounterFn(AtomicU64);

    impl Recorder for FakeRecorder {
        fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}

        /// Registers a counter if the method is on the `self::methods` list and returns it.
        ///
        /// # Warning
        ///
        /// Returns `Counter::noop()` in other cases.
        ///
        /// # Rationale
        /// All tests that are executed concurrently and don't use a `RecorderGuard` of their own
        /// will ultimately attempt at registering their own counters every time they create an instance of `RpcApi`.
        /// This is why it really makes sense to filter out the keys that we don't care about to avoid creating
        /// any additional lock contention. For the other keys that we do care about we should effectively
        /// ignore consecutive attempts to re-register a counter for a given key except the first one,
        /// which means just get the exiting counter instance asap.
        fn register_counter(&self, key: &Key) -> Counter {
            if self.is_key_used(key) {
                // Check if the counter is already registered
                let read_guard = self.0.counters.read().unwrap();
                if let Some(counter) = read_guard.get(key) {
                    // Do nothing, it's already there
                    return Counter::from_arc(counter.clone());
                }
                drop(read_guard);
                // We could still be having some contention on write >here<, but let's assume most of the time
                // the `read()` above does its job
                let mut write_guard = self.0.counters.write().unwrap();
                // Put it there
                // let counter = write_guard.entry(key.clone()).or_default();
                let counter = write_guard.entry(key.clone()).or_insert_with(Arc::default);
                Counter::from_arc(counter.clone())
            } else {
                // We don't care
                Counter::noop()
            }
        }

        fn register_gauge(&self, _: &Key) -> Gauge {
            unimplemented!()
        }
        fn register_histogram(&self, _: &Key) -> Histogram {
            unimplemented!()
        }
    }

    impl FakeRecorder {
        /// Creates a [`FakeRecorder`] which only holds counter values for `methods`.
        ///
        /// All other methods use the [no-op counters](`https://docs.rs/metrics/latest/metrics/struct.Counter.html#method.noop`)
        pub fn new(methods: &'static [&'static str]) -> Self {
            Self(FakeRecorderHandle {
                counters: Arc::default(),
                methods,
            })
        }

        /// Gets the handle to this recorder
        pub fn handle(&self) -> FakeRecorderHandle {
            self.0.clone()
        }

        fn is_key_used(&self, key: &Key) -> bool {
            key.labels().any(|label| {
                label.key() == "method"
                    && self.0.methods.iter().any(|&method| method == label.value())
            })
        }
    }

    impl FakeRecorderHandle {
        /// Panics in any of the following cases
        /// - `counter_name` was not registered via [`metrics::register_counter`]
        /// - `method_name` does not match any [value](https://docs.rs/metrics/latest/metrics/struct.Label.html#method.value)
        /// for the `method` [label](https://docs.rs/metrics/latest/metrics/struct.Label.html#)
        /// [key](https://docs.rs/metrics/latest/metrics/struct.Label.html#method.key)
        /// registered via [`metrics::register_counter`]
        pub fn get_counter_value(
            &self,
            counter_name: &'static str,
            method_name: &'static str,
        ) -> u64 {
            let read_guard = self.counters.read().unwrap();
            read_guard
                .get(&Key::from_parts(
                    counter_name,
                    vec![Label::new("method", method_name)],
                ))
                .unwrap()
                .0
                .load(Ordering::Relaxed)
        }

        /// Panics in any of the following cases
        /// - `counter_name` was not registered via [`metrics::register_counter`]
        /// - `labels` don't match the [label](https://docs.rs/metrics/latest/metrics/struct.Label.html#)-s
        /// registered via [`metrics::register_counter`]
        pub fn get_counter_value_by_label<const N: usize>(
            &self,
            counter_name: &'static str,
            labels: [(&'static str, &'static str); N],
        ) -> u64 {
            let read_guard = self.counters.read().unwrap();
            read_guard
                .get(&Key::from_parts(
                    counter_name,
                    labels
                        .iter()
                        .map(|&(key, val)| Label::new(key, val))
                        .collect::<Vec<_>>(),
                ))
                .unwrap()
                .0
                .load(Ordering::Relaxed)
        }
    }

    impl CounterFn for FakeCounterFn {
        fn increment(&self, val: u64) {
            self.0.fetch_add(val, Ordering::Relaxed);
        }
        fn absolute(&self, _: u64) {
            unimplemented!()
        }
    }
}
