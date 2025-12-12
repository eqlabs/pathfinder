//! Various test utils used in other pathfinder related crates
use fake::{Dummy, Fake, Faker};
use rand::Rng;

/// In order to provide some basic consistency guarantees some containers just
/// cannot be empty
pub fn fake_non_empty_with_rng<C, T>(rng: &mut impl Rng) -> C
where
    C: std::iter::FromIterator<T>,
    T: Dummy<Faker>,
{
    let len = rng.gen_range(1..10);

    std::iter::repeat_with(|| Faker.fake_with_rng(rng))
        .take(len)
        .collect()
}

/// Metrics related test aids
pub mod metrics {
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, RwLock};

    use metrics::{
        Counter,
        CounterFn,
        Gauge,
        Histogram,
        Key,
        KeyName,
        Label,
        Metadata,
        Recorder,
        SharedString,
        Unit,
    };

    /// Mocks a [recorder](`metrics::Recorder`) only for specified
    /// [labels](`metrics::Label`) treating the rest of registered metrics
    /// as _no-op_
    #[derive(Debug, Default)]
    pub struct FakeRecorder(FakeRecorderHandle);

    /// Handle to the [`FakeRecorder`], which allows to get the current value of
    /// counters.
    #[derive(Clone, Debug, Default)]
    pub struct FakeRecorderHandle {
        counters: Arc<RwLock<HashMap<Key, Arc<FakeCounterFn>>>>,
        methods: Option<&'static [&'static str]>,
    }

    #[derive(Debug, Default)]
    struct FakeCounterFn(AtomicU64);

    impl Recorder for FakeRecorder {
        fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}

        /// Registers a counter if the method is on the `self::methods` list and
        /// returns it.
        ///
        /// # Warning
        ///
        /// Returns `Counter::noop()` in other cases.
        fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
            if self.is_key_used(key) {
                // Check if the counter is already registered
                let read_guard = self.0.counters.read().unwrap();
                if let Some(counter) = read_guard.get(key) {
                    // Do nothing, it's already there
                    return Counter::from_arc(counter.clone());
                }
                drop(read_guard);
                // We could still be having some contention on write >here<, but let's assume
                // most of the time the `read()` above does its job
                let mut write_guard = self.0.counters.write().unwrap();
                // Put it there
                // let counter = write_guard.entry(key.clone()).or_default();
                let counter = write_guard.entry(key.clone()).or_default();
                Counter::from_arc(counter.clone())
            } else {
                // We don't care
                Counter::noop()
            }
        }

        fn register_gauge(&self, _: &Key, _metadata: &Metadata<'_>) -> Gauge {
            unimplemented!()
        }
        fn register_histogram(&self, _: &Key, _metadata: &Metadata<'_>) -> Histogram {
            // Ignored in tests for now
            Histogram::noop()
        }
    }

    impl FakeRecorder {
        /// Creates a [`FakeRecorder`] which only holds counter values for
        /// `methods`.
        ///
        /// All other methods use the [no-op counters](`https://docs.rs/metrics/latest/metrics/struct.Counter.html#method.noop`)
        pub fn new_for(methods: &'static [&'static str]) -> Self {
            Self(FakeRecorderHandle {
                counters: Arc::default(),
                methods: Some(methods),
            })
        }

        /// Gets the handle to this recorder
        pub fn handle(&self) -> FakeRecorderHandle {
            self.0.clone()
        }

        fn is_key_used(&self, key: &Key) -> bool {
            match self.0.methods {
                Some(methods) => key.labels().any(|label| {
                    label.key() == "method" && methods.iter().any(|&method| method == label.value())
                }),
                None => true,
            }
        }
    }

    impl FakeRecorderHandle {
        /// Panics in any of the following cases
        /// - `counter_name` was not registered via [`metrics::counter`]
        /// - `method_name` does not match any [value](https://docs.rs/metrics/latest/metrics/struct.Label.html#method.value)
        ///   for the `method` [label](https://docs.rs/metrics/latest/metrics/struct.Label.html#)
        ///   [key](https://docs.rs/metrics/latest/metrics/struct.Label.html#method.key)
        ///   registered via [`metrics::counter`]
        pub fn get_counter_value(
            &self,
            counter_name: &'static str,
            method_name: impl Into<Cow<'static, str>>,
        ) -> u64 {
            let read_guard = self.counters.read().unwrap();
            read_guard
                .get(&Key::from_parts(
                    counter_name,
                    vec![Label::new("method", method_name.into())],
                ))
                .unwrap()
                .0
                .load(Ordering::Relaxed)
        }

        /// Panics in any of the following cases
        /// - `counter_name` was not registered via [`metrics::counter`]
        /// - `labels` don't match the [label](https://docs.rs/metrics/latest/metrics/struct.Label.html#)-s
        ///   registered via [`metrics::counter`]
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
                .expect("Unregistered counter name")
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
