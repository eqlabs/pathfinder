//! Percentage types and operations.
//!
//! # Examples
//!
//! ```
//! use util::percentage::{PercentageDecimal, PercentageInt};
//!
//! let value = 80;
//! let percentage = PercentageInt::new(50);
//! assert_eq!(percentage.of(value), 40);
//!
//! let value = 50.0;
//! let percentage = PercentageDecimal::new(0.5);
//! assert_eq!(percentage.of(value), 25.0);
//! ```

use std::ops::Div;

use num_traits::{CheckedMul, PrimInt};

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct PercentageInt(u8);

impl PercentageInt {
    /// Creates a new `PercentageInt` from an integer value.
    ///
    /// # Panics
    ///
    /// Panics if the value is greater than 100.
    pub fn new(value: u8) -> Self {
        assert!(
            value <= 100,
            "Percentage (int) value must be between 0 and 100"
        );

        Self(value)
    }

    /// Returns a percentage of the given value.
    pub fn of<T>(&self, value: T) -> T
    where
        T: Grow + TryFrom<<T as Grow>::Larger>,
        <T as TryFrom<<T as Grow>::Larger>>::Error: std::fmt::Debug,
    {
        let percentage = value
            .grow()
            .checked_mul(&T::Larger::from(self.0))
            // Should only fail for large u128/i128 values since `.grow()` is a no-op for them.
            // Can be added as a special case in the future if needed.
            .expect("Multiplication should not overflow")
            .div(T::Larger::from(100));

        T::try_from(percentage).expect("Conversion should not fail")
    }

    /// Converts the percentage to a [`PercentageDecimal`].
    pub fn to_decimal(&self) -> PercentageDecimal {
        PercentageDecimal::new(self.0 as f64 / 100.0)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct PercentageDecimal(f64);

impl PercentageDecimal {
    /// Creates a new `PercentageDecimal` from a float value.
    ///
    /// # Panics
    ///
    /// Panics if the value is not between 0.0 and 1.0.
    pub fn new(value: f64) -> Self {
        assert!(
            (0.0..=1.0).contains(&value),
            "Percentage (decimal) value must be between 0.0 and 1.0"
        );

        Self(value)
    }

    /// Returns a percentage of the given value.
    pub fn of(&self, value: f64) -> f64 {
        value * self.0
    }

    /// Converts the percentage to a [`PercentageInt`].
    pub fn to_int(&self) -> PercentageInt {
        PercentageInt::new((self.0 * 100.0).round() as u8)
    }
}

/// Trait for growing primitive integer types to their larger counterparts.
pub trait Grow: PrimInt {
    type Larger: PrimInt + From<u8>;

    fn grow(self) -> Self::Larger;
}

macro_rules! grow_impl {
    ($t:ty, $larger:ty) => {
        impl Grow for $t {
            type Larger = $larger;

            fn grow(self) -> Self::Larger {
                self as $larger
            }
        }
    };
}

grow_impl!(u8, u16);
grow_impl!(u16, u32);
grow_impl!(u32, u64);
grow_impl!(u64, u128);
grow_impl!(u128, u128);

grow_impl!(i8, i16);
grow_impl!(i16, i32);
grow_impl!(i32, i64);
grow_impl!(i64, i128);
grow_impl!(i128, i128);

#[cfg(test)]
mod tests {
    use super::*;

    mod int {
        use super::*;

        #[test]
        fn to_decimal() {
            let percentage = PercentageInt::new(50);
            assert_eq!(percentage.to_decimal(), PercentageDecimal::new(0.5));
        }

        #[test]
        fn unsigned() {
            let percentage = PercentageInt::new(50);
            assert_eq!(percentage.of(80_u8), 40);
            assert_eq!(percentage.of(80_u16), 40);
            assert_eq!(percentage.of(80_u32), 40);
            assert_eq!(percentage.of(80_u64), 40);
            assert_eq!(percentage.of(80_u128), 40);
        }

        #[test]
        fn signed_positive() {
            let percentage = PercentageInt::new(50);
            assert_eq!(percentage.of(80_i8), 40);
            assert_eq!(percentage.of(80_i16), 40);
            assert_eq!(percentage.of(80_i32), 40);
            assert_eq!(percentage.of(80_i64), 40);
            assert_eq!(percentage.of(80_i128), 40);
        }

        #[test]
        fn signed_negative() {
            let percentage = PercentageInt::new(50);
            assert_eq!(percentage.of(-80_i8), -40);
            assert_eq!(percentage.of(-80_i16), -40);
            assert_eq!(percentage.of(-80_i32), -40);
            assert_eq!(percentage.of(-80_i64), -40);
            assert_eq!(percentage.of(-80_i128), -40);
        }

        #[test]
        fn rounding() {
            let percentage = PercentageInt::new(33);
            assert_eq!(percentage.of(80_u8), 26);
        }

        #[should_panic]
        #[test]
        fn new_panic() {
            PercentageInt::new(101);
        }

        #[should_panic]
        #[test]
        fn overflow_panic() {
            let value: u8 = 50;
            let overflow_value = u128::MAX / value as u128 + 1;
            let percentage = PercentageInt::new(value);
            percentage.of(overflow_value);
        }
    }

    mod decimal {
        use super::*;

        #[test]
        fn to_int() {
            let percentage = PercentageDecimal::new(0.5);
            assert_eq!(percentage.to_int(), PercentageInt::new(50));
        }

        #[test]
        fn positive() {
            let percentage = PercentageDecimal::new(0.5);
            assert_eq!(percentage.of(80.0), 40.0);
        }

        #[test]
        fn negative() {
            let percentage = PercentageDecimal::new(0.5);
            assert_eq!(percentage.of(-80.0), -40.0);
        }

        #[test]
        fn unrounded() {
            let percentage = PercentageDecimal::new(0.33);
            assert_eq!(percentage.of(80.0), 26.400000000000002);
        }

        #[should_panic]
        #[test]
        fn new_panic() {
            PercentageDecimal::new(1.1);
        }

        #[should_panic]
        #[test]
        fn new_negative_panic() {
            PercentageDecimal::new(-1.0);
        }
    }
}
