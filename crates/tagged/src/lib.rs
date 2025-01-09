//! Tagging is meant to be used in tests only, but because `[cfg(test)]` cannot
//! be _exported_ we're using the closest build configuration option within the
//! implementation, which is `[cfg(debug_assertions)]`. As an additional safety
//! measure, the [`tagged::init()`](crate::init()) function must be called
//! before using the `tagged::Tagged` type.
#![allow(dead_code)]
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::sync::{Arc, Mutex, MutexGuard, Once};

use fake::{Dummy, Fake, Faker};

/// As much as faking random(-ish) data for tests is pretty convenient,
/// deciphering assertion failures is not so much.
#[derive(Clone, Eq, PartialEq)]
pub struct Tagged<T> {
    pub tag: String,
    pub data: T,
}

impl<T: Debug> Debug for Tagged<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tagged")
            .field("tag", &self.tag)
            .field("data", &self.data)
            .finish()
    }
}

type Lut = Option<Arc<Mutex<HashMap<TypeId, HashMap<String, Box<dyn Any>>>>>>;

static INIT: Once = Once::new();
static mut LUTS: Lut = None;

type LutGuard = MutexGuard<'static, HashMap<TypeId, HashMap<String, Box<dyn Any>>>>;

/// - Does nothing outside Debug builds.
/// - This function __must__ be called before using the [`Tagged`] type, and if
///   one then wants to see the tags in `std::fmt::Debug` output for each type
///   that derives `tagged_debug_derive::TaggedDebug`.
/// - You need to make sure to call this function __at least__ once. Subsequent
///   calls will have no effect.
pub fn init() {
    #[cfg(debug_assertions)]
    INIT.call_once(|| {
        unsafe {
            LUTS = Some(Default::default());
        };
    });
}

fn lut() -> Option<LutGuard> {
    unsafe {
        #[allow(static_mut_refs)]
        LUTS.as_ref()
    }
    .map(|luts| luts.lock().unwrap())
}

impl<T: Clone + 'static> Tagged<T> {
    /// Important
    ///
    /// Use only in Debug builds after calling [`tagged::init`](`crate::init`).
    /// Otherwise this function always returns `None`.
    pub fn get<U: ToString, C: FnOnce() -> T>(_tag: U, _ctor: C) -> Option<Self> {
        #[cfg(debug_assertions)]
        {
            let luts = lut();
            luts.map(|mut luts| {
                let lut = luts.entry(TypeId::of::<T>()).or_default();
                let tag = _tag.to_string();
                let data = lut
                    .entry(tag.clone())
                    .or_insert_with(|| Box::new(_ctor()))
                    .downcast_ref::<T>()
                    .unwrap()
                    .clone();
                Self { tag, data }
            })
        }
        #[cfg(not(debug_assertions))]
        {
            None
        }
    }
}

impl<T: Clone + Dummy<Faker> + 'static> Tagged<T> {
    /// Important
    ///
    /// Use only in Debug builds after calling [`tagged::init`](`crate::init`).
    /// Otherwise this function always returns `None`.
    pub fn get_fake<U: ToString>(_tag: U) -> Option<Self> {
        Self::get(_tag, || Faker.fake())
    }
}

#[derive(Debug)]
pub struct TypeNotFound;

impl<T: Clone + PartialEq + 'static> Tagged<T> {
    /// Important
    ///
    /// Use only in Debug builds after calling [`tagged::init`](`crate::init`).
    /// Otherwise this function will error.
    pub fn from_data(_data: &T) -> Result<Self, TypeNotFound> {
        #[cfg(debug_assertions)]
        {
            let luts = lut().ok_or(TypeNotFound)?;
            let lut = luts.get(&TypeId::of::<T>());

            match lut {
                Some(lut) => {
                    let tag = lut
                        .iter()
                        .find_map(|(k, v)| {
                            v.downcast_ref::<T>()
                                .and_then(|u| (u == _data).then_some(k.clone()))
                        })
                        .unwrap_or("value not found".into());

                    Ok(Self {
                        tag,
                        data: _data.clone(),
                    })
                }
                None => Err(TypeNotFound),
            }
        }
        #[cfg(not(debug_assertions))]
        Err(TypeNotFound)
    }

    /// Important
    ///
    /// Use only in Debug builds after calling [`tagged::init`](`crate::init`).
    /// Otherwise this function will error.
    pub fn tag(data: &T) -> Result<String, TypeNotFound> {
        Self::from_data(data).map(|tagged| tagged.tag)
    }
}

#[cfg(test)]
mod tests {
    use fake::Dummy;
    use pretty_assertions_sorted::assert_eq;
    use tagged_debug_derive::TaggedDebug;

    use super::*;

    #[derive(Clone, Copy, Default, Dummy, PartialEq, TaggedDebug)]
    struct Unit;

    #[derive(Clone, Copy, Default, Dummy, PartialEq, TaggedDebug)]
    struct Tuple(i32, i32);

    #[derive(Clone, Copy, Default, Dummy, PartialEq, TaggedDebug)]
    struct Struct {
        a: i32,
        b: i32,
    }

    #[derive(Clone, Copy, Default, Dummy, PartialEq, TaggedDebug)]
    enum Enum {
        #[default]
        A,
        B(i32, i32),
        C {
            a: i32,
            b: i32,
        },
    }

    #[derive(Clone, Copy, Default, Dummy, PartialEq, TaggedDebug)]
    struct Complex {
        u: Unit,
        t: Tuple,
        e: Enum,
    }

    #[test]
    fn lookup_and_debugs_work_correctly() {
        let unit = Unit;
        let tuple = Tuple(0, 1);
        let stru = Struct { a: 0, b: 1 };
        let enum_unit = Enum::A;
        let enum_tuple = Enum::B(0, 1);
        let enum_struct = Enum::C { a: 2, b: 3 };
        let complex = Complex {
            u: Unit,
            t: Tuple(0, 1),
            e: Enum::C { a: 2, b: 3 },
        };

        // Global lut is not initialized yet, so show default debugs
        assert_eq!(format!("{:?}", unit), "Unit");
        assert_eq!(format!("{:?}", tuple), "Tuple(0, 1)");
        assert_eq!(format!("{:?}", stru), "Struct { a: 0, b: 1 }");
        assert_eq!(format!("{:?}", enum_unit), "A");
        assert_eq!(format!("{:?}", enum_tuple), "B(0, 1)");
        assert_eq!(format!("{:?}", enum_struct), r#"C { a: 2, b: 3 }"#);
        assert_eq!(
            format!("{:?}", complex),
            r#"Complex { u: Unit, t: Tuple(0, 1), e: C { a: 2, b: 3 } }"#
        );

        // Global lut needs to be initialized to cache values and retrieve them
        assert!(Tagged::<Unit>::get("unit", || unit).is_none());
        assert!(Tagged::<Complex>::get_fake("complex").is_none());
        assert!(Tagged::from_data(&complex).is_err());
        assert!(Tagged::tag(&complex).is_err());

        // Init global lut
        crate::init();

        // These types are not registered yet, so still show default debugs
        assert_eq!(format!("{:?}", unit), "Unit");
        assert_eq!(format!("{:?}", tuple), "Tuple(0, 1)");
        assert_eq!(format!("{:?}", stru), "Struct { a: 0, b: 1 }");
        assert_eq!(format!("{:?}", enum_unit), "A");
        assert_eq!(format!("{:?}", enum_tuple), "B(0, 1)");
        assert_eq!(format!("{:?}", enum_struct), r#"C { a: 2, b: 3 }"#);
        assert_eq!(
            format!("{:?}", complex),
            r#"Complex { u: Unit, t: Tuple(0, 1), e: C { a: 2, b: 3 } }"#
        );

        // Register types by inserting at least one value per type, now the debugs for
        // those values should show the tag they were created with
        Tagged::<Unit>::get_fake("unit");
        Tagged::<Tuple>::get("tuple", || tuple);
        Tagged::<Struct>::get("struct", || stru);
        Tagged::<Enum>::get("enum_unit", || enum_unit);
        Tagged::<Enum>::get("enum_tuple", || enum_tuple);
        Tagged::<Enum>::get("enum_struct", || enum_struct);
        Tagged::<Complex>::get("complex", || complex);

        assert_eq!(format!("{:?}", unit), r#"Unit { TAG: "unit" }"#);
        assert_eq!(format!("{:?}", tuple), r#"Tuple("TAG: tuple", 0, 1)"#);
        assert_eq!(
            format!("{:?}", stru),
            r#"Struct { TAG: "struct", a: 0, b: 1 }"#
        );
        assert_eq!(format!("{:?}", enum_unit), r#"A { TAG: "enum_unit" }"#);
        assert_eq!(format!("{:?}", enum_tuple), r#"B("TAG: enum_tuple", 0, 1)"#);
        assert_eq!(
            format!("{:?}", enum_struct),
            r#"C { TAG: "enum_struct", a: 2, b: 3 }"#
        );
        assert_eq!(
            format!("{:?}", complex),
            r#"Complex { TAG: "complex", u: Unit { TAG: "unit" }, t: Tuple("TAG: tuple", 0, 1), e: C { TAG: "enum_struct", a: 2, b: 3 } }"#
        );
    }
}
