use std::sync::Arc;

/// This trait is a workaround for [anyhow::Error] not being cloneable.
///
/// Most of the time you can use `Arc<anyhow::Error>` instead of `anyhow::Error`
/// to circumvent `anyhow::Error` not being `Clone`. However, in some cases, you
/// might need to "unwrap" the Arc-ed error. This trait provides a way to do
/// that.
pub trait AnyhowExt {
    /// Clones the error by doing `to_string` on each item in the chain.
    fn deep_clone(&self) -> anyhow::Error;
    /// Swaps the Arc-ed error for an empty instance using [`Arc::get_mut`] and
    /// if unsuccessful clones the error using
    /// [`AnyhowExt::deep_clone`].
    fn take_or_deep_clone(self: &mut Arc<Self>) -> anyhow::Error;
}

impl AnyhowExt for anyhow::Error {
    fn deep_clone(&self) -> anyhow::Error {
        let mut chain = self.chain().rev();
        let first = chain
            .next()
            .expect("at least one error is always in the chain");

        let mut cloned = anyhow::Error::msg(first.to_string());

        for cause in chain {
            cloned = cloned.context(cause.to_string());
        }

        cloned
    }

    fn take_or_deep_clone(self: &mut Arc<Self>) -> anyhow::Error {
        if let Some(e) = Arc::get_mut(self) {
            let mut taken = anyhow::Error::msg("");
            std::mem::swap(e, &mut taken);
            taken
        } else {
            // The strong ref count is greater than 1
            self.deep_clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> anyhow::Error {
        anyhow::anyhow!("root")
            .context("level 1")
            .context("level 2")
            .context("level 3")
    }

    fn strip_backtrace(s: &str) -> &str {
        let i = s.find("Stack backtrace").unwrap_or(s.len());
        &s[..i]
    }

    #[test]
    fn take_if_refcount_eq1() {
        let src0 = fixture();
        let src = fixture();

        let mut arced = std::sync::Arc::new(src0);
        assert_eq!(Arc::strong_count(&arced), 1);

        // Strong ref count is 1, taking the error should work
        let taken = arced.take_or_deep_clone();
        assert_eq!(format!("{}", taken), format!("{}", src));
        assert_eq!(
            strip_backtrace(&format!("{:?}", taken)),
            strip_backtrace(&format!("{:?}", src))
        );

        assert!(arced.to_string().is_empty());
    }

    #[test]
    fn clone_if_refcount_gt1() {
        let src0 = fixture();
        let src = fixture();

        let mut arced = std::sync::Arc::new(src0);
        let arc_clone = arced.clone();
        assert_eq!(Arc::strong_count(&arc_clone), 2);

        // Strong ref count is 2, only a poor-man's clone is possible
        let cloned = arced.take_or_deep_clone();
        assert_eq!(format!("{}", cloned), format!("{}", src));
        assert_eq!(
            strip_backtrace(&format!("{:?}", arced)),
            strip_backtrace(&format!("{:?}", src))
        );

        assert_eq!(format!("{}", arced), format!("{}", src));
        assert_eq!(
            strip_backtrace(&format!("{:?}", arced)),
            strip_backtrace(&format!("{:?}", src))
        );
    }
}
