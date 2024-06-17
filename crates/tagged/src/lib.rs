use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::sync::{Arc, Mutex, MutexGuard, Once};

use fake::{Dummy, Fake, Faker};

/// As much as faking random(-ish) data for tests is pretty convenient,
/// deciphering assertion failures is not so much.
#[derive(Clone, Eq, PartialEq)]
pub struct Tagged<T> {
    tag: String,
    data: T,
}

impl<T: Debug> Debug for Tagged<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tagged")
            .field("tag", &self.tag)
            .field("data", &self.data)
            .finish()
    }
}

static INIT: Once = Once::new();
static mut LUTS: Option<Arc<Mutex<HashMap<TypeId, HashMap<String, Box<dyn Any>>>>>> = None;

fn lut() -> MutexGuard<'static, HashMap<TypeId, HashMap<String, Box<dyn Any>>>> {
    INIT.call_once(|| {
        unsafe {
            LUTS = Some(Default::default());
        };
    });

    unsafe { LUTS.as_ref().unwrap().lock().unwrap() }
}

impl<T: Clone + 'static> Tagged<T> {
    pub fn get<U: ToString, C: FnOnce() -> T>(tag: U, ctor: C) -> Self {
        let mut luts = lut();
        let lut = luts.entry(TypeId::of::<T>()).or_default();
        let tag = tag.to_string();
        let data = lut
            .entry(tag.clone())
            .or_insert_with(|| Box::new(ctor()))
            .downcast_ref::<T>()
            .unwrap()
            .clone();
        Self { tag, data }
    }
}

impl<T: Clone + Dummy<Faker> + 'static> Tagged<T> {
    pub fn get_fake<U: ToString>(tag: U) -> Self {
        Self::get(tag, || Faker.fake())
    }
}

#[derive(Debug)]
pub struct TypeNotFound;

impl<T: Clone + PartialEq + 'static> Tagged<T> {
    pub fn tagged(data: &T) -> Result<Self, TypeNotFound> {
        let luts = lut();
        let lut = luts.get(&TypeId::of::<T>());

        match lut {
            Some(lut) => {
                let tag = lut
                    .iter()
                    .find_map(|(k, v)| {
                        v.downcast_ref::<T>()
                            .and_then(|u| (u == data).then_some(k.clone()))
                    })
                    .unwrap_or("value not found".into());

                Ok(Self {
                    tag,
                    data: data.clone(),
                })
            }
            None => Err(TypeNotFound),
        }
    }

    pub fn tag(data: &T) -> Result<String, TypeNotFound> {
        Self::tagged(data).map(|tagged| tagged.tag)
    }
}

#[cfg(test)]
mod tests {
    use fake::Dummy;
    use pretty_assertions_sorted::assert_eq;
    use tagged_debug_derive::TaggedDebug;

    use super::*;

    #[derive(Clone, Default, Dummy, PartialEq, TaggedDebug)]
    struct Unit;

    #[derive(Clone, Default, Dummy, PartialEq, TaggedDebug)]
    struct Tuple(i32, i32);

    #[derive(Clone, Default, Dummy, PartialEq, TaggedDebug)]
    struct Struct {
        a: i32,
        b: i32,
    }

    #[derive(Clone, Default, Dummy, PartialEq, TaggedDebug)]
    enum Enum {
        #[default]
        A,
        B(i32, i32),
        C {
            a: i32,
            b: i32,
        },
    }

    #[derive(Clone, Default, Dummy, PartialEq, TaggedDebug)]
    struct Complex {
        u: Unit,
        t: Tuple,
        e: Enum,
    }

    #[test]
    fn lookup_works_correctly() {
        #[derive(Clone, Default, Dummy, PartialEq, TaggedDebug)]
        struct Foo {
            a: i32,
        }

        #[derive(Clone, Default, Debug, Dummy, PartialEq)]
        struct Unregistered {
            u: u32,
        }

        // A tag points to the same value
        let foo = Tagged::<Foo>::get_fake("foo");
        let foo2 = Tagged::<Foo>::get_fake("foo");
        assert_eq!(foo, foo2);

        // Retagging a cached value
        let retagged = Tagged::tagged(&foo.data).unwrap();
        assert_eq!(foo, retagged);

        // Retagging an uncached value
        assert_eq!(
            Tagged::tag(&Faker.fake::<Foo>()).unwrap(),
            "value not found"
        );

        // Retagging an uncached type fails
        assert!(Tagged::tagged(&Faker.fake::<Unregistered>()).is_err());
    }

    #[test]
    fn shown_tag_in_debug_when_type_found() {
        // Types are not registered yet, so show default debugs
        assert_eq!(format!("{:?}", Unit), "Unit");

        assert_eq!(format!("{:?}", Tuple(0, 1)), "Tuple(0, 1)");

        assert_eq!(
            format!("{:?}", Struct { a: 0, b: 1 }),
            "Struct { a: 0, b: 1 }"
        );

        assert_eq!(format!("{:?}", Enum::A), "A");

        assert_eq!(format!("{:?}", Enum::B(0, 1)), "B(0, 1)");

        assert_eq!(
            format!("{:?}", Enum::C { a: 2, b: 3 }),
            r#"C { a: 2, b: 3 }"#
        );

        assert_eq!(
            format!(
                "{:?}",
                Complex {
                    u: Unit,
                    t: Tuple(0, 1),
                    e: Enum::C { a: 2, b: 3 }
                }
            ),
            r#"Complex { u: Unit, t: Tuple(0, 1), e: C { a: 2, b: 3 } }"#
        );

        // Register types, now they should also display the tag they were created with
        assert_eq!(
            format!("{:?}", Tagged::<Unit>::get_fake("unit")),
            r#"Tagged { tag: "unit", data: Unit { TAG: "unit" } }"#
        );

        assert_eq!(
            format!("{:?}", Tagged::<Tuple>::get("tuple", || Tuple(0, 1))),
            r#"Tagged { tag: "tuple", data: Tuple("TAG: tuple", 0, 1) }"#
        );

        assert_eq!(
            format!(
                "{:?}",
                Tagged::<Struct>::get("struct", || Struct { a: 0, b: 1 })
            ),
            r#"Tagged { tag: "struct", data: Struct { TAG: "struct", a: 0, b: 1 } }"#
        );

        assert_eq!(
            format!("{:?}", Tagged::<Enum>::get("enum_unit", || Enum::A)),
            r#"Tagged { tag: "enum_unit", data: A { TAG: "enum_unit" } }"#
        );

        assert_eq!(
            format!("{:?}", Tagged::<Enum>::get("enum_tuple", || Enum::B(0, 1))),
            r#"Tagged { tag: "enum_tuple", data: B("TAG: enum_tuple", 0, 1) }"#
        );

        assert_eq!(
            format!(
                "{:?}",
                Tagged::<Enum>::get("enum_struct", || Enum::C { a: 2, b: 3 })
            ),
            r#"Tagged { tag: "enum_struct", data: C { TAG: "enum_struct", a: 2, b: 3 } }"#
        );

        assert_eq!(
            format!(
                "{:?}",
                Tagged::<Complex>::get("complex", || Complex {
                    u: Unit,
                    t: Tuple(0, 1),
                    e: Enum::C { a: 2, b: 3 }
                })
            ),
            r#"Tagged { tag: "complex", data: Complex { TAG: "complex", u: Unit { TAG: "unit" }, t: Tuple("TAG: tuple", 0, 1), e: C { TAG: "enum_struct", a: 2, b: 3 } } }"#
        );
    }
}
