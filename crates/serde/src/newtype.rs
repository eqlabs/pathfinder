pub trait NewType<T> {
    fn into_inner(self) -> T;
    fn from_inner(inner: T) -> Self;
}

newtype!(pathfinder_common::ClassHash: stark_hash::Felt,);

macro_rules! newtype {
    ($target:ty: $inner:ty $(,)?) => {
        impl NewType<$inner> for $target {
            fn into_inner(self) -> $inner {
                self.0
            }

            fn from_inner(inner: $inner) -> Self {
                Self(inner)
            }
        }
    };
    ($head:ty, $($tail:ty),+ $(,)?) => {
        newtype!($head);
        newtype!($($tail),+);
    };
}

use newtype;
