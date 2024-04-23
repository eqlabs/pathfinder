use crate::algebra::field::MontFelt;
use crate::hash::poseidon::consts::*;

/// State for the Poseidon hash function
pub type PoseidonState = [MontFelt; 3];

const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 83;

/// Poseidon mix function.
///
/// The MixLayer operation using MDS matrix M = ((3,1,1), (1,-1,1), (1,1,-2)).
/// Given state vector x=(a,b,c), it returns Mx, optimized by precomputing
/// t=a+b+c.
#[inline(always)]
fn mix(state: &mut PoseidonState) {
    let t = state[0] + state[1] + state[2];
    state[0] = t + state[0].double();
    state[1] = t - state[1].double();
    state[2] = t - (state[2].double() + state[2]);
}

/// Poseidon full round function.
///
/// Each round consists of three steps:
///   - AddRoundConstants adds precomputed constants
///   - SubWords is the cube function
///   - MixLayer multiplies the state with fixed matrix
#[inline]
fn full_round(state: &mut PoseidonState, idx: usize) {
    state[0] += POSEIDON_COMP_CONSTS[idx];
    state[1] += POSEIDON_COMP_CONSTS[idx + 1];
    state[2] += POSEIDON_COMP_CONSTS[idx + 2];
    state[0] = state[0].square() * state[0];
    state[1] = state[1].square() * state[1];
    state[2] = state[2].square() * state[2];
    mix(state);
}

/// Poseidon partial round function.
///
/// This only applies the non-linear part to a partial state.
#[inline]
fn partial_round(state: &mut PoseidonState, idx: usize) {
    state[2] += POSEIDON_COMP_CONSTS[idx];
    state[2] = state[2].square() * state[2];
    mix(state);
}

/// Poseidon permutation function
///
/// The permutation consists of 8 full rounds, 83 partial rounds followed by 8
/// full rounds.
pub fn permute(state: &mut PoseidonState) {
    let mut idx = 0;

    // Full rounds
    for _ in 0..(FULL_ROUNDS / 2) {
        full_round(state, idx);
        idx += 3;
    }

    // Partial rounds
    for _ in 0..PARTIAL_ROUNDS {
        partial_round(state, idx);
        idx += 1;
    }

    // Full rounds
    for _ in 0..(FULL_ROUNDS / 2) {
        full_round(state, idx);
        idx += 3;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::field::MontFelt;

    #[test]
    fn test_poseidon() {
        // Test vector from https://github.com/starkware-industries/poseidon
        let test_result = [
            MontFelt::from_hex("79E8D1E78258000A28FC9D49E233BC6852357968577B1E386550ED6A9086133"),
            MontFelt::from_hex("3840D003D0F3F96DBB796FF6AA6A63BE5B5404B91CCAABCA256154CBB6FB984"),
            MontFelt::from_hex("1EB39DA3F7D3B04142D0AC83D9DA00C9325A61FB2EF326E50B70EAA8A3C7CC7"),
        ];
        let mut state: PoseidonState = [MontFelt::ZERO, MontFelt::ZERO, MontFelt::ZERO];
        permute(&mut state);
        assert_eq!(state, test_result);
    }
}
