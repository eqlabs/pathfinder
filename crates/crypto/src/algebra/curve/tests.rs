use bitvec::view::AsBits;

use crate::algebra::curve::affine::affine_point_str;
use crate::algebra::curve::projective::projective_point_str;
use crate::algebra::curve::{AffinePoint, ProjectivePoint, CURVE_G};

#[test]
fn affine_projective_multiply() {
    let value = [3u64];
    let three = value.as_bits();

    let ag = AffinePoint::from(&CURVE_G);
    let ag_triple = ag.multiply(three);

    let pg = ProjectivePoint::from(&ag);
    let pg_triple = pg.multiply(three);

    let result = AffinePoint::from(&pg_triple);
    assert_eq!(ag_triple.x, result.x);
}

#[test]
fn projective_double() {
    let g_double = {
        let mut g = CURVE_G;
        g.double();
        AffinePoint::from(&g)
    };
    let expected = affine_point_str!(
        "3324833730090626974525872402899302150520188025637965566623476530814354734325",
        "3147007486456030910661996439995670279305852583596209647900952752170983517249"
    );
    assert_eq!(g_double, expected);
}

#[test]
fn projective_double_and_add() {
    let g_triple = {
        let mut g = CURVE_G;
        g.double();
        g.add(&CURVE_G);
        AffinePoint::from(&g)
    };
    let expected = affine_point_str!(
        "1839793652349538280924927302501143912227271479439798783640887258675143576352",
        "3564972295958783757568195431080951091358810058262272733141798511604612925062"
    );
    assert_eq!(g_triple, expected);
}

#[test]
fn projective_multiply() {
    let value = [3u64];
    let three = value.as_bits();
    let g = CURVE_G;
    let g_triple = AffinePoint::from(&g.multiply(three));
    let expected = affine_point_str!(
        "1839793652349538280924927302501143912227271479439798783640887258675143576352",
        "3564972295958783757568195431080951091358810058262272733141798511604612925062"
    );
    assert_eq!(g_triple, expected);
}

#[test]
fn const_generator() {
    let expected = projective_point_str!(
        "874739451078007766457464989774322083649278607533249481151382481072868806602",
        "152666792071518830868575557812948353041420400780739481342941381225525861407"
    );
    assert_eq!(CURVE_G, expected);
}
