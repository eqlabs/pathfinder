//! Generators for the Pedersen hash function.
//!
//! See <https://docs.starkware.co/starkex/crypto/pedersen-hash-function.html>
use crate::algebra::curve::ProjectivePoint;

/// Montgomery representation of the Stark curve constant P0.
pub const PEDERSEN_P0: ProjectivePoint = ProjectivePoint::from_hex(
    "49EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804",
    "3CA0CFE4B3BC6DDF346D49D06EA0ED34E621062C0E056C1D0405D266E10268A",
);

/// Montgomery representation of the Stark curve constant P1.
pub const PEDERSEN_P1: ProjectivePoint = ProjectivePoint::from_hex(
    "234287DCBAFFE7F969C748655FCA9E58FA8120B6D56EB0C1080D17957EBE47B",
    "3B056F100F96FB21E889527D41F4E39940135DD7A6C94CC6ED0268EE89E5615",
);

/// Montgomery representation of the Stark curve constant P2.
pub const PEDERSEN_P2: ProjectivePoint = ProjectivePoint::from_hex(
    "4FA56F376C83DB33F9DAB2656558F3399099EC1DE5E3018B7A6932DBA8AA378",
    "3FA0984C931C9E38113E0C0E47E4401562761F92A7A23B45168F4E80FF5B54D",
);

/// Montgomery representation of the Stark curve constant P3.
pub const PEDERSEN_P3: ProjectivePoint = ProjectivePoint::from_hex(
    "4BA4CC166BE8DEC764910F75B45F74B40C690C74709E90F3AA372F0BD2D6997",
    "40301CF5C1751F4B971E46C4EDE85FCAC5C59A5CE5AE7C48151F27B24B219C",
);

/// Montgomery representation of the Stark curve constant P4.
pub const PEDERSEN_P4: ProjectivePoint = ProjectivePoint::from_hex(
    "54302DCB0E6CC1C6E44CCA8F61A63BB2CA65048D53FB325D36FF12C49A58202",
    "1B77B3E37D13504B348046268D8AE25CE98AD783C25561A879DCC77E99C2426",
);
