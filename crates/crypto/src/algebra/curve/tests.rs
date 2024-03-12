use bitvec::view::AsBits;

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
fn affine_double() {
    let g_double = {
        let mut g = AffinePoint::from(&CURVE_G);
        g.double();
        g
    };
    let expected = AffinePoint::from_hex(
        "759CA09377679ECD535A81E83039658BF40959283187C654C5416F439403CF5",
        "6F524A3400E7708D5C01A28598AD272E7455AA88778B19F93B562D7A9646C41",
    );
    assert_eq!(g_double, expected);
}

#[test]
fn projective_double() {
    let g_double = {
        let mut g = CURVE_G;
        g.double();
        AffinePoint::from(&g)
    };
    let expected = AffinePoint::from_hex(
        "759CA09377679ECD535A81E83039658BF40959283187C654C5416F439403CF5",
        "6F524A3400E7708D5C01A28598AD272E7455AA88778B19F93B562D7A9646C41",
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
    let expected = AffinePoint::from_hex(
        "411494B501A98ABD8262B0DA1351E17899A0C4EF23DD2F96FEC5BA847310B20",
        "7E1B3EBAC08924D2C26F409549191FCF94F3BF6F301ED3553E22DFB802F0686",
    );
    assert_eq!(g_triple, expected);
}

#[test]
fn projective_multiply() {
    let value = [3u64];
    let three = value.as_bits();
    let g = CURVE_G;
    let g_triple = AffinePoint::from(&g.multiply(three));
    let expected = AffinePoint::from_hex(
        "411494B501A98ABD8262B0DA1351E17899A0C4EF23DD2F96FEC5BA847310B20",
        "7E1B3EBAC08924D2C26F409549191FCF94F3BF6F301ED3553E22DFB802F0686",
    );
    assert_eq!(g_triple, expected);
}

#[test]
fn const_generator() {
    let expected = ProjectivePoint::from_hex(
        "1EF15C18599971B7BECED415A40F0C7DEACFD9B0D1819E03D723D8BC943CFCA",
        "5668060AA49730B7BE4801DF46EC62DE53ECD11ABE43A32873000C36E8DC1F",
    );
    assert_eq!(CURVE_G, expected);
}
