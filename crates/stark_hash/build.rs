use std::env;
use std::fmt::Write;
use std::fs;
use std::path::Path;

use stark_curve::*;

fn generate_consts(bits: u32) -> Result<String, std::fmt::Error> {
    let mut buf = String::with_capacity(10 * 1024 * 1024);

    write!(buf, "pub const CURVE_CONSTS_BITS: usize = {bits};\n\n")?;

    push_points(&mut buf, "P1", &PEDERSEN_P1, 248, bits)?;
    buf.push_str("\n\n\n");
    push_points(&mut buf, "P2", &PEDERSEN_P2, 4, bits)?;
    buf.push_str("\n\n\n");
    push_points(&mut buf, "P3", &PEDERSEN_P3, 248, bits)?;
    buf.push_str("\n\n\n");
    push_points(&mut buf, "P4", &PEDERSEN_P4, 4, bits)?;

    Ok(buf)
}

fn push_points(
    buf: &mut String,
    name: &str,
    base: &ProjectivePoint,
    max_bits: u32,
    bits: u32,
) -> std::fmt::Result {
    let base = AffinePoint::from(base);

    let full_chunks = max_bits / bits;
    let leftover_bits = max_bits % bits;
    let table_size_full = (1 << bits) - 1;
    let table_size_leftover = (1 << leftover_bits) - 1;
    let len = full_chunks * table_size_full + table_size_leftover;

    writeln!(
        buf,
        "pub const CURVE_CONSTS_{name}: [AffinePoint; {len}] = ["
    )?;

    let mut bits_left = max_bits;
    let mut outer_point = base;
    while bits_left > 0 {
        let eat_bits = std::cmp::min(bits_left, bits);
        let table_size = (1 << eat_bits) - 1;

        println!("Processing {eat_bits} bits, remaining: {bits_left}");

        // Loop through each possible bit combination except zero
        let mut inner_point = outer_point.clone();
        for j in 1..(table_size + 1) {
            if bits_left < max_bits || j > 1 {
                buf.push_str(",\n");
            }
            push_point(buf, &inner_point)?;
            inner_point.add(&outer_point);
        }

        // Shift outer point #bits times
        bits_left -= eat_bits;
        for _i in 0..bits {
            outer_point.double();
        }
    }

    buf.push_str("\n];");
    Ok(())
}

fn push_point(buf: &mut String, p: &AffinePoint) -> std::fmt::Result {
    let x = p.x.inner();
    let y = p.y.inner();
    buf.push_str("    AffinePoint::new(");
    buf.push_str("\n        [");
    write!(buf, "\n            {},", x[0])?;
    write!(buf, "\n            {},", x[1])?;
    write!(buf, "\n            {},", x[2])?;
    write!(buf, "\n            {},", x[3])?;
    buf.push_str("\n        ],");
    buf.push_str("\n        [");
    write!(buf, "\n            {},", y[0])?;
    write!(buf, "\n            {},", y[1])?;
    write!(buf, "\n            {},", y[2])?;
    write!(buf, "\n            {},", y[3])?;
    buf.push_str("\n        ]");
    buf.push_str("\n    )");
    Ok(())
}

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("curve_consts.rs");
    let bits = 4;
    let consts = generate_consts(bits).expect("should had been able to format the curve constants");
    fs::write(dest_path, consts)
        .expect("should had been able to write to $OUT_DIR/curve_consts.rs");
}
