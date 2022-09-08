pub mod middleware {
    use jsonrpsee::core::middleware::Middleware;

    #[derive(Debug, Clone)]
    pub struct RpcMetricsMiddleware;

    impl Middleware for RpcMetricsMiddleware {
        type Instant = ();

        fn on_request(&self) -> Self::Instant {}

        fn on_call(&self, name: &str) {
            metrics::increment_counter!("rpc_method_calls_total", "method" => name.to_owned());
        }

        fn on_result(&self, name: &str, _success: bool, _started_at: Self::Instant) {
            if !_success {
                metrics::increment_counter!("rpc_method_calls_failed_total", "method" => name.to_owned());
            }
        }
    }

    #[derive(Debug, Clone)]
    pub enum MaybeRpcMetricsMiddleware {
        Middleware(RpcMetricsMiddleware),
        NoOp,
    }

    impl jsonrpsee::core::middleware::Middleware for MaybeRpcMetricsMiddleware {
        type Instant = ();

        fn on_request(&self) -> Self::Instant {}

        fn on_call(&self, name: &str) {
            match self {
                MaybeRpcMetricsMiddleware::Middleware(x) => x.on_call(name),
                MaybeRpcMetricsMiddleware::NoOp => {}
            }
        }

        fn on_result(&self, name: &str, success: bool, started_at: Self::Instant) {
            match self {
                MaybeRpcMetricsMiddleware::Middleware(x) => x.on_result(name, success, started_at),
                MaybeRpcMetricsMiddleware::NoOp => {}
            }
        }
    }
}

#[cfg(test)]
pub mod test {
    use metrics::{Recorder, SetRecorderError};
    use std::sync::{Mutex, MutexGuard};

    static RECORDER_LOCK: Mutex<()> = Mutex::new(());

    /// Allows to safely set a `metrics::Recorder` for a particular test.
    /// The recorder will be removed when this guard is dropped.
    /// Internal mutex protects us from inter-test recorder races.
    pub struct RecorderGuard<'a>(MutexGuard<'a, ()>);

    impl<'a> RecorderGuard<'a> {
        /// Locks the global mutex and sets the global `metrics::Recorder` for the current test.
        /// The global recorder is cleared and the mutex is unlocked when the guard is dropped.
        ///
        /// The `recorder` passed to this function will be moved onto the heap and then __leaked__
        /// but we don't really care as this is purely a testing aid.
        pub fn lock<R>(recorder: R) -> Result<Self, SetRecorderError>
        where
            R: Recorder + 'static,
        {
            let guard = RECORDER_LOCK.lock().unwrap();

            metrics::set_boxed_recorder(Box::new(recorder))?;

            Ok(Self(guard))
        }
    }

    impl<'a> Drop for RecorderGuard<'a> {
        fn drop(&mut self) {
            unsafe { metrics::clear_recorder() }
        }
    }
}
