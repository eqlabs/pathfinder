/// An opaque wrapper type that is used to describe foreign-key constraints.
///
/// Storage tables should return [ForeignKey<T>] (if required) for insert and get
/// operations. This in turn lets another table require this type for its foreign-key
/// to enforce that the user has checked that it exists.
pub struct ForeignKey<T>(pub(super) T);

impl<T> std::ops::Deref for ForeignKey<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> Clone for ForeignKey<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Copy for ForeignKey<T> where T: Copy {}

impl<T> Default for ForeignKey<T>
where
    T: Default,
{
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<T> std::fmt::Debug for ForeignKey<T>
where
    T: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ForeignKey").field(&self.0).finish()
    }
}

impl<T> std::fmt::Display for ForeignKey<T>
where
    T: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("ForeignKey({})", &self.0))
    }
}
