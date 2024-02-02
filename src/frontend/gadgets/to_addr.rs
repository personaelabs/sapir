use super::bitops::form_le_bits;
use crate::frontend::constraint_system::Wire;
use crate::frontend::gadgets::bitops::{not_a_and_b_64, rotate_left_64, xor_64};
use ark_ff::Field;
use std::ops::Add;

// Keccak256 parameters in bits
pub const ROUNDS: usize = 24;
const OUTPUT_LEN: usize = 256;
const CAPACITY: usize = OUTPUT_LEN * 2;
const STATE_WIDTH: usize = 1600;
pub const RATE: usize = STATE_WIDTH - CAPACITY;

// Table 2 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
pub const RHO_OFFSETS: [[u32; 5]; 5] = [
    [0, 1, 190, 28, 91],
    [36, 300, 6, 55, 276],
    [3, 10, 171, 153, 231],
    [105, 45, 15, 21, 136],
    [210, 66, 253, 120, 78],
];

// Copied from https://github.com/debris/tiny-keccak/blob/master/src/keccakf.rs
pub const RC: [u64; ROUNDS] = [
    1u64,
    0x8082u64,
    0x800000000000808au64,
    0x8000000080008000u64,
    0x808bu64,
    0x80000001u64,
    0x8000000080008081u64,
    0x8000000000008009u64,
    0x8au64,
    0x88u64,
    0x80008009u64,
    0x8000000au64,
    0x8000808bu64,
    0x800000000000008bu64,
    0x8000000000008089u64,
    0x8000000000008003u64,
    0x8000000000008002u64,
    0x8000000000000080u64,
    0x800au64,
    0x800000008000000au64,
    0x8000000080008081u64,
    0x8000000000008080u64,
    0x80000001u64,
    0x8000000080008008u64,
];

pub fn to_addr<F: Field>(input: [Wire<F>; 512]) -> Wire<F> {
    let cs = input[0].cs();
    let zero = cs.zero();
    let one = cs.one();

    // Pad
    let mut pad = [zero; RATE - 512];
    pad[0] = cs.one();
    pad[pad.len() - 1] = cs.one();

    let mut padded_input = [zero; 1600];
    padded_input[..512].copy_from_slice(&input);
    padded_input[512..(512 + pad.len())].copy_from_slice(&pad);

    let mut state = [[zero; 64]; 25];

    for i in 0..25 {
        state[i] = padded_input[i * 64..(i + 1) * 64].try_into().unwrap();
    }

    // Assign the round constants
    let rc: [[Wire<F>; 64]; 24] = RC.map(|c| {
        let mut c_assigned = Vec::with_capacity(64);
        for i in 0..64 {
            if c >> i & 1 == 1 {
                c_assigned.push(one);
            } else {
                c_assigned.push(zero);
            }
        }

        c_assigned.try_into().unwrap()
    });

    for i in 0..ROUNDS {
        // Theta
        let mut c = [[zero; 64]; 5];
        let mut d = [[zero; 64]; 5];

        for y in 0..5 {
            for x in 0..5 {
                c[x] = xor_64(c[x], state[x + y * 5]);
            }
        }

        for x in 0..5 {
            d[x] = xor_64(c[(x + 4) % 5], rotate_left_64(c[(x + 1) % 5], 1));
        }

        for y in 0..5 {
            for x in 0..5 {
                state[x + y * 5] = xor_64(state[x + y * 5], d[x]);
            }
        }

        // ############################################
        // Rho
        // ############################################
        let mut rho_x = 0;
        let mut rho_y = 1;
        for _ in 0..24 {
            // Rotate each lane by an offset
            let index = rho_x + 5 * rho_y;
            state[index] = rotate_left_64(state[index], (RHO_OFFSETS[rho_y][rho_x] % 64) as usize);

            let rho_x_prev = rho_x;
            rho_x = rho_y;
            rho_y = (2 * rho_x_prev + 3 * rho_y) % 5;
        }

        // ############################################
        // Pi
        // ############################################

        let state_cloned = state.clone();
        for y in 0..5 {
            for x in 0..5 {
                let index = ((x + 3 * y) % 5) + x * 5;
                state[x + y * 5] = state_cloned[index];
            }
        }

        // ############################################
        // Chi
        // ############################################

        let state_cloned = state.clone();
        for y in 0..5 {
            for x in 0..5 {
                let index = x + y * 5;
                state[index] = xor_64(
                    state_cloned[index],
                    not_a_and_b_64(
                        state_cloned[(x + 1) % 5 + y * 5],
                        state_cloned[(x + 2) % 5 + y * 5],
                    ),
                );
            }
        }

        // ############################################
        // Iota
        // ############################################

        state[0] = xor_64(state[0], rc[i]);
    }

    let mut address_bits = vec![];
    let state_1 = state[1][32..].to_vec();
    let state_2 = state[2].to_vec();
    let state_3 = state[3].to_vec();

    address_bits.extend_from_slice(&state_1);
    address_bits.extend_from_slice(&state_2);
    address_bits.extend_from_slice(&state_3);

    let mut out = cs.zero();
    let mut pow = F::ONE;
    for (i, bits) in address_bits.chunks(8).rev().enumerate() {
        let byte = form_le_bits(&bits);
        let term = cs.mul_const(byte, pow);
        out = out.add(term);

        pow = F::from(2u32).pow(&[8 * ((i + 1) as u64)]);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{frontend::constraint_system::ConstraintSystem, test_var_pub_input};
    use ark_ff::Field;
    use num_bigint::BigUint;
    type F = ark_secq256k1::Fr;

    fn to_addr_circuit<F: Field>(cs: &mut ConstraintSystem<F>) {
        let pub_key_bits = cs.alloc_priv_inputs(512);

        let addr = to_addr(pub_key_bits.try_into().unwrap());
        cs.expose_public(addr);
    }

    #[test]
    fn test_to_addr() {
        // Public key which underlies dantehrani.eth
        let pub_key_str = "765b012d6340fd3baf3068e3e118a68a559b832af2d9ddd05585fedcf9f9c2a95a65f71708281d9e1517e28c3643fa932d7675a233d8cc4edc3440c10684cd95";
        let pub_key_bytes = hex::decode(pub_key_str).unwrap();

        let expected_address_str = "400ea6522867456e988235675b9cb5b1cf5b79c8";
        let expected_address = hex::decode(expected_address_str).unwrap();

        let pub_key_bits = pub_key_bytes
            .iter()
            .map(|b| {
                // Little-endian bits
                let mut bits = Vec::with_capacity(8);
                for i in 0..8 {
                    bits.push(if (*b >> i) & 1 == 1 { F::ONE } else { F::ZERO });
                }

                bits
            })
            .flatten()
            .collect::<Vec<F>>();

        let synthesizer = |cs: &mut ConstraintSystem<F>| {
            to_addr_circuit(cs);
        };

        let priv_input = pub_key_bits;
        let addr = F::from(BigUint::from_bytes_be(&expected_address));
        let pub_input = [addr];

        test_var_pub_input(synthesizer, &pub_input, &priv_input);
    }
}
