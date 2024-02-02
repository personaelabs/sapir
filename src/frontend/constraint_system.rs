use crate::r1cs::{Matrix, SparseMatrixEntry, R1CS};
use crate::timer::{profiler_end, profiler_start};
use ark_ff::Field;
use core::panic;
use std::cmp::max;
use std::collections::BTreeMap;

pub struct Conditional<F: Field> {
    undecided: Wire<F>,
    out: Wire<F>,
}

impl<F: Field> Conditional<F> {
    pub fn if_then(sel: Wire<F>, out: Wire<F>, cs: &mut ConstraintSystem<F>) -> Self {
        cs.assert_binary(sel);

        let out = sel * out;

        Self {
            undecided: !sel,
            out,
        }
    }

    pub fn elif(&self, sel: Wire<F>, out: Wire<F>, cs: &mut ConstraintSystem<F>) -> Self {
        cs.assert_binary(sel);

        let this_cond = sel * out;
        let out = cs.mul_add(self.undecided, this_cond, self.out);
        let undecided = !sel & self.undecided;

        Self { undecided, out }
    }

    pub fn else_then(&self, out: Wire<F>) -> Wire<F> {
        let cs = self.out.cs();
        cs.mul_add(self.undecided, out, self.out)
    }
}

#[derive(Clone, Copy)]
pub struct Wire<F: Field> {
    id: usize,
    pub index: usize,
    cs: *mut ConstraintSystem<F>,
}

use std::fmt::Debug;

impl<F: Field> Debug for Wire<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cs = self.cs();
        if cs.mode == Mode::WitnessGen && cs.phase == Phase::Synthesize {
            let val = cs.wires[self.index];
            write!(f, "Wire({})", val).unwrap();
            println!("phase {:?}", cs.phase);
        }

        Ok(())
    }
}

unsafe impl<F: Field> Send for Wire<F> {}

impl<F: Field> Wire<F> {
    pub fn new(id: usize, index: usize, cs: *mut ConstraintSystem<F>) -> Self {
        Wire { id, index, cs }
    }

    pub fn cs(&self) -> &mut ConstraintSystem<F> {
        unsafe { &mut *self.cs as &mut ConstraintSystem<F> }
    }

    pub fn div_or_zero(&self, w: Wire<F>) -> Wire<F> {
        w.cs().div_or_zero(*self, w)
    }

    pub fn is_zero(&self) -> Wire<F> {
        self.cs().is_zero(*self)
    }

    pub fn is_equal(&self, w: Wire<F>) -> Wire<F> {
        self.cs().is_equal(*self, w)
    }

    pub fn assert_zero(&self, cs: &mut ConstraintSystem<F>) {
        cs.assert_zero(*self)
    }

    pub fn assert_equal(&self, w: Wire<F>, cs: &mut ConstraintSystem<F>) {
        cs.assert_equal(*self, w, "")
    }

    pub fn and(&self, w: Wire<F>, cs: &mut ConstraintSystem<F>) -> Wire<F> {
        cs.and(*self, w)
    }

    pub fn or(&self, w: Wire<F>, cs: &mut ConstraintSystem<F>) -> Wire<F> {
        cs.or(*self, w)
    }

    pub fn not(&self, cs: &mut ConstraintSystem<F>) -> Wire<F> {
        cs.not(*self)
    }

    pub fn print(&self) {
        if self.cs().mode == Mode::WitnessGen {
            let val = self.cs().wires[self.index];
            if val == F::ZERO {
                print!("0");
            } else {
                print!("{}", self.cs().wires[self.index]);
            }
        }
    }

    pub fn println(&self, label: &str) {
        if self.cs().mode == Mode::WitnessGen {
            let val = self.cs().wires[self.index];
            if val == F::ZERO {
                println!("{}: 0", label);
            } else {
                println!("{}: {}", label, self.cs().wires[self.index]);
            }
        }
    }

    pub fn val(&self, cs: &mut ConstraintSystem<F>) -> Option<F> {
        if cs.mode == Mode::WitnessGen {
            Some(cs.wires[self.index])
        } else {
            None
        }
    }
}

use std::ops::{Add, AddAssign, BitAnd, BitOr, Div, Mul, MulAssign, Neg, Not, Sub, SubAssign};

impl<F: Field> Add<Wire<F>> for Wire<F> {
    type Output = Wire<F>;

    fn add(self, rhs: Wire<F>) -> Self::Output {
        self.cs().add(self, rhs)
    }
}

impl<F: Field> AddAssign<Wire<F>> for Wire<F> {
    fn add_assign(&mut self, rhs: Wire<F>) {
        *self = self.cs().add(*self, rhs);
    }
}

impl<F: Field> Sub<Wire<F>> for Wire<F> {
    type Output = Wire<F>;

    fn sub(self, rhs: Wire<F>) -> Self::Output {
        self.cs().sub(self, rhs)
    }
}

impl<F: Field> SubAssign<Wire<F>> for Wire<F> {
    fn sub_assign(&mut self, rhs: Wire<F>) {
        *self = self.cs().sub(*self, rhs);
    }
}

impl<F: Field> Mul<Wire<F>> for Wire<F> {
    type Output = Wire<F>;

    fn mul(self, rhs: Wire<F>) -> Self::Output {
        self.cs().mul(self, rhs)
    }
}

impl<F: Field> MulAssign<Wire<F>> for Wire<F> {
    fn mul_assign(&mut self, rhs: Wire<F>) {
        *self = self.cs().mul(*self, rhs);
    }
}

impl<F: Field> Div<Wire<F>> for Wire<F> {
    type Output = Wire<F>;

    fn div(self, rhs: Wire<F>) -> Self::Output {
        self.cs().div(self, rhs)
    }
}

impl<F: Field> Neg for Wire<F> {
    type Output = Wire<F>;

    fn neg(self) -> Self::Output {
        self.cs().neg(self)
    }
}

impl<F: Field> BitAnd for Wire<F> {
    type Output = Wire<F>;

    fn bitand(self, rhs: Wire<F>) -> Self::Output {
        self.cs().and(self, rhs)
    }
}

impl<F: Field> BitOr for Wire<F> {
    type Output = Wire<F>;

    fn bitor(self, rhs: Wire<F>) -> Self::Output {
        self.cs().or(self, rhs)
    }
}

impl<F: Field> Not for Wire<F> {
    type Output = Wire<F>;

    fn not(self) -> Self::Output {
        self.cs().not(self)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CircuitMeta {
    pub num_pub_inputs: usize,
    pub num_priv_inputs: usize,
    pub num_constraints: usize,
    pub num_variables: usize,
}

#[derive(Debug, Clone, PartialEq)]
enum Phase {
    Idle,
    CounterWires,
    Synthesize,
}

#[derive(Clone, PartialEq)]
enum Mode {
    Idle,
    WitnessGen,
    ConstraintsGen,
}

// A constraint system (R1CS) that handles the followings:
// - Allocating and constraining wires (by exposing methods `add`, `mul`, etc.)
// - Generating the witness (`gen_witness`)
// - Generating the R1CS instance (`gen_constraints`)
// The circuit writer should define a "synthesizer" that takes a mutable reference
// to a `ConstraintSystem` and calls its method to allocate and constrain wires.
#[derive(Clone)]
pub struct ConstraintSystem<F: Field> {
    pub wires: Vec<F>,
    A_first: BTreeMap<usize, F>,
    B_first: BTreeMap<usize, F>,
    C_first: BTreeMap<usize, F>,
    A: BTreeMap<u64, F>,
    B: BTreeMap<u64, F>,
    C: BTreeMap<u64, F>,
    A_nonzero_coeffs: Vec<Vec<usize>>,
    B_nonzero_coeffs: Vec<Vec<usize>>,
    C_nonzero_coeffs: Vec<Vec<usize>>,
    constants: BTreeMap<F, (usize, usize)>,
    pub next_priv_wire: usize,
    pub next_pub_wire: usize,
    next_constraint: usize,
    next_wire_id: usize,
    phase: Phase,
    mode: Mode,
    pub num_constraints: Option<usize>,
    num_total_wires: Option<usize>,
    num_pub_inputs: Option<usize>,
    num_priv_inputs: Option<usize>,
    pub_wires: Vec<usize>,
    constrained: bool,
    wires_counted: bool,
}

impl<F: Field> ConstraintSystem<F> {
    const ONE_WIRE_INDEX: usize = 0;

    pub const fn new() -> Self {
        ConstraintSystem {
            wires: vec![],
            A_first: BTreeMap::new(),
            B_first: BTreeMap::new(),
            C_first: BTreeMap::new(),
            A: BTreeMap::new(),
            B: BTreeMap::new(),
            C: BTreeMap::new(),
            A_nonzero_coeffs: Vec::new(),
            B_nonzero_coeffs: Vec::new(),
            C_nonzero_coeffs: Vec::new(),
            constants: BTreeMap::new(),
            next_priv_wire: 0,
            next_pub_wire: 0,
            next_wire_id: 1,
            phase: Phase::Idle,
            mode: Mode::Idle,
            num_total_wires: None,
            num_priv_inputs: None,
            num_pub_inputs: None,
            num_constraints: None,
            pub_wires: vec![],
            next_constraint: 1,
            wires_counted: false,
            constrained: false,
        }
    }

    pub fn is_witness_gen(&self) -> bool {
        self.mode == Mode::WitnessGen
    }

    fn alloc_wire(&mut self) -> Wire<F> {
        let wire = if self.phase == Phase::CounterWires {
            self.num_total_wires = self.num_total_wires.map_or(Some(2), |x| Some(x + 1));
            Wire::new(self.next_wire_id, 0, self) // Set the index to 0 for now
        } else {
            let wire_index = if self.pub_wires.contains(&self.next_wire_id) {
                // If the next wire is a exposed later, allocate a public wire
                let next_pub_wire = self.next_pub_wire;
                self.next_pub_wire += 1;
                next_pub_wire
            } else {
                let next_priv_wire = self.next_priv_wire;
                self.next_priv_wire += 1;
                next_priv_wire
            };
            Wire::new(self.next_wire_id, wire_index, self)
        };

        self.next_wire_id += 1;
        wire
    }

    // Allocate an unconstrained variable.
    // Use `alloc_const` to allocate a constant value.
    pub fn alloc_var(&mut self, val: F) -> Wire<F> {
        let wire = self.alloc_wire();
        if self.is_witness_gen() {
            self.wires[wire.index] = val;
        }
        wire
    }

    // Allocate a private value and return the index of the allocated wire
    pub fn alloc_priv_input(&mut self) -> Wire<F> {
        let wire = self.alloc_wire();
        if self.phase == Phase::CounterWires {
            self.num_priv_inputs = self.num_priv_inputs.map_or(Some(1), |x| Some(x + 1));
            wire
        } else {
            wire
        }
    }

    pub fn alloc_priv_inputs(&mut self, n: usize) -> Vec<Wire<F>> {
        (0..n).map(|_| self.alloc_priv_input()).collect()
    }

    // Allocate a public input wire.
    pub fn alloc_pub_input(&mut self) -> Wire<F> {
        let wire = if self.phase == Phase::CounterWires {
            self.num_total_wires = self.num_total_wires.map_or(Some(2), |x| Some(x + 1));
            self.num_pub_inputs = self.num_pub_inputs.map_or(Some(1), |x| Some(x + 1));
            Wire::new(self.next_wire_id, 0, self) // Set the index to 0 for now
        } else if self.phase == Phase::Synthesize {
            let wire = Wire::new(self.next_wire_id, self.next_pub_wire, self);
            self.next_pub_wire += 1;
            wire
        } else {
            panic!("Constraint system is't initialized");
        };

        self.next_wire_id += 1;
        wire
    }

    pub fn alloc_pub_inputs(&mut self, n: usize) -> Vec<Wire<F>> {
        (0..n).map(|_| self.alloc_pub_input()).collect()
    }

    // Expose a wire as a public input.
    pub fn expose_public(&mut self, wire: Wire<F>) {
        if self.phase == Phase::CounterWires {
            self.num_pub_inputs = self.num_pub_inputs.map_or(Some(1), |x| Some(x + 1));
            // We need to count wires so we know which wires to expose.
            self.pub_wires.push(wire.id);
        }
    }

    // Allocate a constant value.
    pub fn alloc_const(&mut self, c: F) -> Wire<F> {
        if let Some((id, index)) = self.constants.get(&c) {
            Wire::new(*id, *index, self)
        } else {
            let one = self.one();
            let constant = self.mul_const(one, c);
            self.constants.insert(c, (constant.id, constant.index));
            constant
        }
    }

    pub fn one(&mut self) -> Wire<F> {
        Wire::new(0, Self::ONE_WIRE_INDEX, self)
    }

    pub fn zero(&mut self) -> Wire<F> {
        self.alloc_const(F::ZERO)
    }

    fn next_constraint_offset(&mut self) -> u64 {
        let next_constraint = self.next_constraint;
        self.next_constraint += 1;

        (next_constraint as u64) * (self.z_len() as u64)
    }

    // Assert that the given wire is binary at witness generation.
    // It does NOT constraint the wire to be binary.
    fn assert_binary(&self, w: Wire<F>) {
        if self.is_witness_gen() {
            let assigned_w = self.wires[w.index];
            if assigned_w != F::ZERO && assigned_w != F::ONE {
                println!("Wire '{}' should be binary, but is {:?}", w.id, assigned_w);
            }
        }
    }

    fn increment_tree_val(tree: &mut BTreeMap<usize, F>, key: usize, val: F) {
        if let Some(v) = tree.get(&key) {
            tree.insert(key, *v + val);
        } else {
            tree.insert(key, val);
        }
    }

    pub fn add(&mut self, w1: Wire<F>, w2: Wire<F>) -> Wire<F> {
        let w3 = self.alloc_wire();

        if self.phase == Phase::Synthesize {
            if self.is_witness_gen() {
                // If this is a witness generation call,
                // we assign the output of the gate here.
                self.wires[w3.index] = self.wires[w1.index] + self.wires[w2.index];
            } else {
                // (w1 + w2) * 1 - w3 = 0
                Self::increment_tree_val(&mut self.A_first, w1.index, F::ONE);
                Self::increment_tree_val(&mut self.A_first, w2.index, F::ONE);
                Self::increment_tree_val(&mut self.C_first, w3.index, F::ONE);
            }
        }

        w3
    }

    pub fn sum(&mut self, wires: &[(Wire<F>, bool)]) -> Wire<F> {
        let w3 = self.alloc_wire();

        if self.phase == Phase::Synthesize {
            if self.is_witness_gen() {
                // If this is a witness generation call,
                // we assign the output of the gate here.
                let mut sum = F::ZERO;
                for (w, sign) in wires {
                    if *sign {
                        sum += self.wires[w.index];
                    } else {
                        sum -= self.wires[w.index];
                    }
                }
                self.wires[w3.index] = sum;
            } else {
                // (w1 + w2 + ... + w_n) * 1 - w3 = 0
                for (w, sign) in wires {
                    let increment_by = if *sign { F::ONE } else { -F::ONE };
                    Self::increment_tree_val(&mut self.A_first, w.index, increment_by);
                }

                Self::increment_tree_val(&mut self.C_first, w3.index, F::ONE);
            }
        }

        w3
    }

    pub fn add_const(&mut self, w1: Wire<F>, c: F) -> Wire<F> {
        let w2 = self.alloc_wire();

        if self.phase == Phase::Synthesize {
            if self.is_witness_gen() {
                self.wires[w2.index] = self.wires[w1.index] + c;
            } else {
                // (w1 + c) * 1 - w2 = 0
                Self::increment_tree_val(&mut self.A_first, w1.index, F::ONE);
                Self::increment_tree_val(&mut self.A_first, Self::ONE_WIRE_INDEX, c);
                Self::increment_tree_val(&mut self.C_first, w2.index, F::ONE);
            }
        }

        w2
    }

    pub fn sub(&mut self, w1: Wire<F>, w2: Wire<F>) -> Wire<F> {
        let w3 = self.alloc_wire();

        if self.phase == Phase::Synthesize {
            if self.is_witness_gen() {
                self.wires[w3.index] = self.wires[w1.index] - self.wires[w2.index];
            } else {
                // (w1 - w2) * 1 - w3 = 0
                Self::increment_tree_val(&mut self.A_first, w1.index, F::ONE);
                Self::increment_tree_val(&mut self.A_first, w2.index, -F::ONE);
                Self::increment_tree_val(&mut self.C_first, w3.index, F::ONE);
            }
        }

        w3
    }

    // Subtract a constant value from a wire.
    pub fn sub_const(&mut self, w1: Wire<F>, c: F) -> Wire<F> {
        let w2 = self.alloc_wire();

        if self.phase == Phase::Synthesize {
            if self.is_witness_gen() {
                self.wires[w2.index] = self.wires[w1.index] - c;
            } else {
                // (w1 - c) * 1 - w2 = 0
                Self::increment_tree_val(&mut self.A_first, w1.index, F::ONE);
                Self::increment_tree_val(&mut self.A_first, Self::ONE_WIRE_INDEX, -c);
                Self::increment_tree_val(&mut self.C_first, w2.index, F::ONE);
            }
        }

        w2
    }

    pub fn neg(&mut self, w: Wire<F>) -> Wire<F> {
        let w2 = self.alloc_wire();

        if self.phase == Phase::Synthesize {
            if self.is_witness_gen() {
                self.wires[w2.index] = -self.wires[w.index];
            } else {
                // w * (1 * -1) - w2 = 0

                let con = self.next_constraint_offset();

                let a_key = con + (w.index as u64);
                let b_key = con + Self::ONE_WIRE_INDEX as u64;
                let c_key = con + w2.index as u64;

                self.A.insert(a_key, F::ONE);
                self.B.insert(b_key, -F::ONE);
                self.C.insert(c_key, F::ONE);

                self.A_nonzero_coeffs.push(vec![w.index]);
                self.B_nonzero_coeffs.push(vec![Self::ONE_WIRE_INDEX]);
                self.C_nonzero_coeffs.push(vec![w2.index]);
            }
        }

        w2
    }

    // Add a degree 2 constraint.
    // `a`, `b`, and `c` are linear combination of wires
    // that should satisfy the constraint `a * b + c = 0`.
    pub fn constrain(
        &mut self,
        a: &[(Wire<F>, F)],
        b: &[(Wire<F>, F)],
        c: &[(Wire<F>, F)],
    ) -> Wire<F> {
        let w3 = self.alloc_wire();

        if self.phase == Phase::Synthesize {
            if self.is_witness_gen() {
                let a_comb: F = a.iter().map(|(w, c)| self.wires[w.index] * c).sum();
                let b_comb: F = b.iter().map(|(w, c)| self.wires[w.index] * c).sum();
                let c_comb: F = c.iter().map(|(w, c)| self.wires[w.index] * c).sum();
                self.wires[w3.index] = a_comb * b_comb + c_comb;
            } else {
                let con = self.next_constraint_offset();

                for a_i in a {
                    let a_key = con + a_i.0.index as u64;
                    self.A.insert(a_key, a_i.1);
                }

                for b_i in b {
                    let b_key = con + b_i.0.index as u64;
                    self.B.insert(b_key, b_i.1);
                }

                for c_i in c {
                    let c_key = con + c_i.0.index as u64;
                    self.C.insert(c_key, -c_i.1);
                }

                let c_key = con + w3.index as u64;
                self.C.insert(c_key, F::ONE);

                let a_nonzero_coeffs = a.iter().map(|(w, _)| w.index).collect();
                let b_nonzero_coeffs = b.iter().map(|(w, _)| w.index).collect();
                let mut c_nonzero_coeffs: Vec<usize> = c.iter().map(|(w, _)| w.index).collect();
                c_nonzero_coeffs.push(w3.index);

                self.A_nonzero_coeffs.push(a_nonzero_coeffs);
                self.B_nonzero_coeffs.push(b_nonzero_coeffs);
                self.C_nonzero_coeffs.push(c_nonzero_coeffs);
            }
        }

        w3
    }

    pub fn mul(&mut self, w1: Wire<F>, w2: Wire<F>) -> Wire<F> {
        let w3 = self.alloc_wire();

        if self.phase == Phase::Synthesize {
            if self.is_witness_gen() {
                self.wires[w3.index] = self.wires[w1.index] * self.wires[w2.index];
            } else {
                // w1 * w2 - w3 = 0
                let con = self.next_constraint_offset();

                let a_key = con + w1.index as u64;
                let b_key = con + w2.index as u64;
                let c_key = con + w3.index as u64;

                self.A.insert(a_key, F::ONE);
                self.B.insert(b_key, F::ONE);
                self.C.insert(c_key, F::ONE);

                self.A_nonzero_coeffs.push(vec![w1.index]);
                self.B_nonzero_coeffs.push(vec![w2.index]);
                self.C_nonzero_coeffs.push(vec![w3.index]);
            }
        }

        w3
    }

    // Multiply a wire by a constant value
    pub fn mul_const(&mut self, w1: Wire<F>, c: F) -> Wire<F> {
        let w3 = self.alloc_wire();
        if self.phase == Phase::Synthesize {
            if self.is_witness_gen() {
                self.wires[w3.index] = self.wires[w1.index] * c;
            } else {
                // w1 * c - w3 = 0

                // w1 * w2 - w3 = 0
                let con = self.next_constraint_offset();

                let a_key = con + w1.index as u64;
                let b_key = con + Self::ONE_WIRE_INDEX as u64;
                let c_key = con + w3.index as u64;

                self.A.insert(a_key, c);
                self.B.insert(b_key, F::ONE);
                self.C.insert(c_key, F::ONE);

                self.A_nonzero_coeffs.push(vec![w1.index]);
                self.B_nonzero_coeffs.push(vec![Self::ONE_WIRE_INDEX]);
                self.C_nonzero_coeffs.push(vec![w3.index]);
            }
        }

        w3
    }

    // w1 * w2 + w3
    pub fn mul_add(&mut self, w1: Wire<F>, w2: Wire<F>, w3: Wire<F>) -> Wire<F> {
        let out = self.alloc_wire();

        if self.phase == Phase::Synthesize {
            if self.is_witness_gen() {
                self.wires[out.index] =
                    self.wires[w1.index] * self.wires[w2.index] + self.wires[w3.index];
            } else {
                // w1 * w2 - ((-1 * w3) + out)  = 0
                let con = self.next_constraint_offset();

                let a_key = con + w1.index as u64;
                let b_key = con + w2.index as u64;
                let c_key = con + w3.index as u64;
                let out_key = con + out.index as u64;

                self.A.insert(a_key, F::ONE);
                self.B.insert(b_key, F::ONE);
                self.C.insert(c_key, -F::ONE);
                self.C.insert(out_key, F::ONE);

                self.A_nonzero_coeffs.push(vec![w1.index]);
                self.B_nonzero_coeffs.push(vec![w2.index]);
                self.C_nonzero_coeffs.push(vec![w3.index, out.index]);
            }
        }

        out
    }

    pub fn square(&mut self, w: Wire<F>) -> Wire<F> {
        w * w
    }

    // This function will panic if the denominator is zero.
    // Use `div_or_zero` to handle division by zero.
    pub fn div(&mut self, w1: Wire<F>, w2: Wire<F>) -> Wire<F> {
        let w2_inv = self.alloc_wire();

        if self.phase == Phase::Synthesize {
            if self.is_witness_gen() {
                let inv = self.wires[w2.index].inverse();
                if inv.is_none().into() {
                    panic!("Division by zero at {} / {}", w1.id, w2.id);
                }

                self.wires[w2_inv.index] = inv.unwrap();
            }
        }

        let w3 = w1 * w2_inv;
        let one = self.one();
        self.assert_equal(w2 * w2_inv, one, "");

        w3
    }

    // If the denominator is zero, the output is assigned to zero.
    pub fn div_or_zero(&mut self, w1: Wire<F>, w2: Wire<F>) -> Wire<F> {
        let w2_inv = self.alloc_wire();

        if self.phase == Phase::Synthesize {
            if self.is_witness_gen() {
                if self.wires[w2.index] == F::ZERO {
                    self.wires[w2_inv.index] = F::ZERO;
                } else {
                    self.wires[w2_inv.index] = self.wires[w2.index].inverse().unwrap();
                }
            }
        }

        let w3 = w1 * w2_inv;

        let conditional = !(w2.is_zero());
        self.assert_equal(w2 * w2_inv, conditional, "");

        w3
    }

    pub fn assert_equal(&mut self, w1: Wire<F>, w2: Wire<F>, msg: &str) {
        if self.phase == Phase::Synthesize {
            if self.is_witness_gen() {
                let assigned_w1 = self.wires[w1.index];
                let assigned_w2 = self.wires[w2.index];

                if assigned_w1 != assigned_w2 {
                    panic!("{}", msg);
                }
            } else {
                let con = self.next_constraint_offset();

                // W1 * 1 == w2

                let a_key = con + w1.index as u64;
                let b_key = con + Self::ONE_WIRE_INDEX as u64;
                let c_key = con + w2.index as u64;

                self.A.insert(a_key, F::ONE);
                self.B.insert(b_key, F::ONE);
                self.C.insert(c_key, F::ONE);

                self.A_nonzero_coeffs.push(vec![w1.index]);
                self.B_nonzero_coeffs.push(vec![Self::ONE_WIRE_INDEX]);
                self.C_nonzero_coeffs.push(vec![w2.index]);
            }
        }
    }

    pub fn is_equal(&mut self, w1: Wire<F>, w2: Wire<F>) -> Wire<F> {
        (w1 - w2).is_zero()
    }

    // Start a conditional block.
    // The conditional block must be ended by calling `else_then`.
    pub fn if_then(&mut self, sel: Wire<F>, out: Wire<F>) -> Conditional<F> {
        Conditional::if_then(sel, out, self)
    }

    pub fn assert_zero(&mut self, w: Wire<F>) {
        if self.phase == Phase::Synthesize {
            if self.is_witness_gen() {
                let assigned_w = self.wires[w.index];
                if assigned_w != F::ZERO {
                    panic!("{:?} should be zero but is {:?}", w.id, assigned_w);
                }
            } else {
                // W * W = 0

                let con = self.next_constraint_offset();

                let a_key = con + w.index as u64;
                let b_key = con + w.index as u64;
                let c_key = con + Self::ONE_WIRE_INDEX as u64;

                self.A.insert(a_key, F::ONE);
                self.B.insert(b_key, F::ONE);
                self.C.insert(c_key, F::ZERO);

                self.A_nonzero_coeffs.push(vec![w.index]);
                self.B_nonzero_coeffs.push(vec![w.index]);
                self.C_nonzero_coeffs.push(vec![Self::ONE_WIRE_INDEX]);
            }
        }
    }

    // Return a binary wire that is 1 if the input wire is zero and 0 otherwise.
    pub fn is_zero(&mut self, w: Wire<F>) -> Wire<F> {
        // Taking the same approach as the IsZero template form circomlib

        let inv = self.alloc_wire();
        if self.is_witness_gen() {
            let assigned_w = self.wires[w.index];
            if assigned_w == F::ZERO {
                self.wires[inv.index] = F::ZERO;
            } else {
                self.wires[inv.index] = assigned_w.inverse().unwrap();
            };
        }

        let one = self.one();

        // out = -w * inv + 1
        let out = self.constrain(&[(w, -F::ONE)], &[(inv, F::ONE)], &[(one, F::ONE)]);

        self.assert_zero(out * w);
        out
    }

    // Returns `w1 AND w2`.
    // It does NOT constraint the input wires to be binary.
    pub fn and(&mut self, w1: Wire<F>, w2: Wire<F>) -> Wire<F> {
        self.assert_binary(w1);
        self.assert_binary(w2);
        w1 * w2
    }

    // Returns `w1 OR w2`.
    // It does NOT constraint the input wires to be binary.
    pub fn or(&mut self, w1: Wire<F>, w2: Wire<F>) -> Wire<F> {
        (w1 + w2) - (w1 * w2)
    }

    // Returns `!w`.
    // It does NOT constraint the input wires to be binary.
    pub fn not(&mut self, w: Wire<F>) -> Wire<F> {
        self.assert_binary(w);
        let one = self.one();
        one - w
    }

    // Return the number of private wires
    pub fn num_vars(&self) -> usize {
        if self.num_total_wires.is_none() {
            panic!("Number of wires not yet counted");
        }

        self.num_total_wires.unwrap() - self.num_pub_inputs.unwrap_or(0) - 1
    }

    fn det_priv_wires_offset(num_total_wires: usize, num_pub_inputs: usize) -> usize {
        // We do +1 to account for the wire that is always "1".
        let num_pub_wires = num_pub_inputs + 1;
        let num_priv_wires = num_total_wires - num_pub_wires;

        max(num_pub_wires, num_priv_wires).next_power_of_two()
    }

    fn priv_wires_offset(&self) -> usize {
        if self.num_total_wires.is_none() {
            panic!("Number of wires not yet counted");
        }

        Self::det_priv_wires_offset(
            self.num_total_wires.unwrap(),
            self.num_pub_inputs.unwrap_or(0),
        )
    }

    fn z_len(&self) -> usize {
        self.priv_wires_offset() * 2
    }

    fn count_wires<S: Fn(&mut ConstraintSystem<F>)>(&mut self, synthesizer: &S) {
        if !self.wires_counted {
            self.phase = Phase::CounterWires;
            (synthesizer)(self);

            self.wires_counted = true;
        }
    }

    // Generate the witness
    pub fn gen_witness<S: Fn(&mut ConstraintSystem<F>)>(
        &mut self,
        synthesizer: S,
        pub_inputs: &[F],
        priv_inputs: &[F],
    ) -> Vec<F> {
        self.count_wires(&synthesizer);

        // Check the number of public inputs
        if self.num_pub_inputs.unwrap() != pub_inputs.len() {
            panic!(
                "Number of public inputs does not match. Expected {}, got {}",
                self.num_pub_inputs.unwrap(),
                pub_inputs.len()
            );
        }

        // Check the number of private inputs
        if self.num_priv_inputs.unwrap() != priv_inputs.len() {
            panic!(
                "Number of private inputs does not match. Expected {}, got {}",
                self.num_priv_inputs.unwrap(),
                priv_inputs.len()
            );
        }

        // Assign public and private inputs to the wires
        self.wires = [&[F::ONE], pub_inputs].concat().to_vec();
        self.wires.resize(self.priv_wires_offset(), F::ZERO);
        self.wires.extend_from_slice(priv_inputs);
        self.wires.resize(self.z_len(), F::ZERO);

        self.synthesize(&synthesizer, Mode::WitnessGen);

        let witness = self.wires[self.priv_wires_offset()..].to_vec();

        witness
    }

    pub fn set_constraints<S: Fn(&mut ConstraintSystem<F>)>(&mut self, synthesizer: &S) {
        if self.constrained {
            panic!("Constraints already set");
        }

        self.count_wires(&synthesizer);

        let gen_constraints_timer = profiler_start("Generating constraints");
        self.synthesize(synthesizer, Mode::ConstraintsGen);
        profiler_end(gen_constraints_timer);

        // If no public inputs were allocated, we set the number of public inputs to 0.
        if self.num_pub_inputs.is_none() {
            self.num_pub_inputs = Some(0);
        }

        self.constrained = true;
    }

    pub fn to_r1cs(&self) -> R1CS<F> {
        if !self.constrained {
            panic!("Constraints not yet set");
        }

        let constructing_r1cs = profiler_start("Constructing R1CS");

        let mut A_entries = vec![];
        let mut B_entries = vec![];
        let mut C_entries = vec![];

        // First constraint

        for coeff_i in self.A_first.keys() {
            A_entries.push(SparseMatrixEntry {
                row: 0,
                col: *coeff_i,
                val: *self.A_first.get(coeff_i).unwrap(),
            });
        }

        for coeff_i in self.B_first.keys() {
            B_entries.push(SparseMatrixEntry {
                row: 0,
                col: *coeff_i,
                val: *self.B_first.get(coeff_i).unwrap(),
            });
        }

        for coeff_i in self.C_first.keys() {
            C_entries.push(SparseMatrixEntry {
                row: 0,
                col: *coeff_i,
                val: *self.C_first.get(coeff_i).unwrap(),
            });
        }

        for con in 1..self.num_constraints.unwrap() {
            let offset = con as u64 * self.z_len() as u64;
            for coeff_i in &self.A_nonzero_coeffs[con - 1] {
                A_entries.push(SparseMatrixEntry {
                    row: con,
                    col: *coeff_i,
                    val: *self.A.get(&(*coeff_i as u64 + offset)).unwrap(),
                });
            }

            for coeff_i in &self.B_nonzero_coeffs[con - 1] {
                B_entries.push(SparseMatrixEntry {
                    row: con,
                    col: *coeff_i,
                    val: *self.B.get(&(*coeff_i as u64 + offset)).unwrap(),
                });
            }

            for coeff_i in &self.C_nonzero_coeffs[con - 1] {
                C_entries.push(SparseMatrixEntry {
                    row: con,
                    col: *coeff_i,
                    val: *self.C.get(&(*coeff_i as u64 + offset)).unwrap(),
                });
            }
        }

        let num_cols = self.z_len();
        let num_rows = self.num_constraints.unwrap();

        let A = Matrix {
            entries: A_entries,
            num_rows,
            num_cols,
        };

        let B = Matrix {
            entries: B_entries,
            num_rows,
            num_cols,
        };

        let C = Matrix {
            entries: C_entries,
            num_rows,
            num_cols,
        };

        profiler_end(constructing_r1cs);

        R1CS {
            A,
            B,
            C,
            num_input: self.num_pub_inputs.unwrap_or(0),
            num_vars: self.num_vars(),
        }
    }

    fn synthesize<S: Fn(&mut ConstraintSystem<F>)>(&mut self, synthesizer: &S, mode: Mode) {
        if !self.wires_counted {
            panic!("Number of wires not yet counted");
        }

        self.mode = mode;
        self.next_wire_id = 1;
        self.next_priv_wire = self.priv_wires_offset();
        self.next_pub_wire = 1;
        self.phase = Phase::Synthesize;

        // The value `one` in the first row of the B matrix is always enabled.
        self.B_first.insert(Self::ONE_WIRE_INDEX, F::ONE);

        // `constants` is updated for wire counting, witness generation and constraint generation,
        // so we need to clear it before running the synthesizer.
        self.constants.clear();

        // Run the synthesizer
        (synthesizer)(self);

        if self.mode == Mode::ConstraintsGen {
            self.num_constraints = Some(self.next_constraint);
        }
    }

    pub fn is_sat(&mut self, witness: &[F], public_input: &[F]) -> bool {
        let z = R1CS::construct_z(witness, public_input);

        if !self.constrained {
            panic!("Constraints not yet set");
        }

        // Check the first constraint, which encodes all the additions

        let A_first_eval = self
            .A_first
            .keys()
            .map(|coeff| z[*coeff] * self.A_first.get(coeff).unwrap())
            .sum::<F>();

        let B_first_eval = self
            .B_first
            .keys()
            .map(|coeff| z[*coeff] * self.B_first.get(coeff).unwrap())
            .sum::<F>();

        let C_first_eval = self
            .C_first
            .keys()
            .map(|coeff| z[*coeff] * self.C_first.get(coeff).unwrap())
            .sum::<F>();

        if A_first_eval * B_first_eval != C_first_eval {
            println!("First constraint not satisfied");
            return false;
        }

        // Check rest of the constraints
        for con in 1..self.num_constraints.unwrap() {
            let offset = con as u64 * self.z_len() as u64;
            let A_eval: F = self.A_nonzero_coeffs[con - 1]
                .iter()
                .map(|coeff| z[*coeff] * self.A.get(&(*coeff as u64 + offset)).unwrap())
                .sum();

            let B_eval: F = self.B_nonzero_coeffs[con - 1]
                .iter()
                .map(|coeff| z[*coeff] * self.B.get(&(*coeff as u64 + offset)).unwrap())
                .sum();

            let C_eval: F = self.C_nonzero_coeffs[con - 1]
                .iter()
                .map(|coeff| z[*coeff] * self.C.get(&(*coeff as u64 + offset)).unwrap())
                .sum();

            if A_eval * B_eval != C_eval {
                println!(
                    "Constraint {} not satisfied, {} * {} != {}",
                    con, A_eval, B_eval, C_eval
                );
                return false;
            }
        }

        true
    }
}

#[macro_export]
macro_rules! init_constraint_system {
    ($field:ty) => {
        pub use std::sync::Mutex;

        static CONSTRAINT_SYSTEM: Mutex<ConstraintSystem<$field>> =
            Mutex::new(ConstraintSystem::new());
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::test_utils::{synthetic_circuit, test_satisfiability, test_var_pub_input};
    use ark_ff::Field;

    type F = ark_secq256k1::Fr;

    #[test]
    fn test_phase_count_wires() {
        let (synthesizer, _, _, _) = synthetic_circuit();
        let mut cs = ConstraintSystem::<F>::new();

        cs.phase = Phase::CounterWires;
        (synthesizer)(&mut cs);

        assert_eq!(cs.num_total_wires, Some(8));
        assert_eq!(cs.num_priv_inputs, Some(1));
        assert_eq!(cs.num_pub_inputs, Some(3));
    }

    #[test]
    fn test_private_wires_offset() {
        // Test that the constraint system correctly determines the offset
        // where private wires start

        // Case 1
        let num_total_wires = 3;
        let num_pub_inputs = 1;
        // num_priv_wires = 3 - (1 + 1) = 1
        let offset = ConstraintSystem::<F>::det_priv_wires_offset(num_total_wires, num_pub_inputs);
        assert_eq!(offset, 2);

        // Case 2
        let num_total_wires = 4;
        let num_pub_inputs = 1;
        // num_priv_wires = 4 - (1 + 1) = 2
        let offset = ConstraintSystem::<F>::det_priv_wires_offset(num_total_wires, num_pub_inputs);
        assert_eq!(offset, 2);

        // Case 3
        let num_total_wires = 4;
        let num_pub_inputs = 2;
        // num_priv_wires = 4 - (2 + 1) = 1
        let offset = ConstraintSystem::<F>::det_priv_wires_offset(num_total_wires, num_pub_inputs);
        assert_eq!(offset, 4);
    }

    #[test]
    fn test_gen_witness() {
        let (synthesizer, pub_inputs, priv_inputs, expected_witness) = synthetic_circuit();
        let mut cs = ConstraintSystem::<F>::new();

        let witness = cs.gen_witness(synthesizer, &pub_inputs, &priv_inputs);

        assert_eq!(cs.priv_wires_offset(), 4);
        assert_eq!(witness, expected_witness);
    }

    // ########################################
    // ########## Test the primitive operations ############
    // ########################################

    // Test the primitive operations `add`, `sub`, and `div`.
    // `mul` is for some reason a private function in `F` so we cannot test it here.
    macro_rules! test_op {
        ($op:ident) => {
            // Test $op
            let synthesizer = |cs: &mut ConstraintSystem<_>| {
                let a = cs.alloc_priv_input();
                let b = cs.alloc_priv_input();

                // a $op b = c
                let c = a.$op(b);

                cs.expose_public(c);
            };

            let a = F::from(3u32);
            let b = F::from(4u32);
            let c = a.$op(b);
            let priv_inputs = [a, b];
            let pub_inputs = [c];
            test_satisfiability(synthesizer, &pub_inputs, &priv_inputs);
        };
    }

    // Test the primitive operations `add_assign`, `sub_assign`, and `div_assign`.
    // `mul_assign` is for some reason a private function in `F` so we cannot test it here.
    macro_rules! test_op_assign {
        ($op_assign:ident) => {
            // Test $op_assign
            let synthesizer = |cs: &mut ConstraintSystem<_>| {
                let a = cs.alloc_priv_input();
                let b = cs.alloc_priv_input();

                // a $op b = c
                let a = a.$op_assign(b);

                cs.expose_public(a);
            };
            let a = F::from(3u32);
            let b = F::from(4u32);
            let a_assigned = a.$op_assign(b);
            let priv_inputs = [a, b];
            let pub_inputs = [a_assigned];
            test_satisfiability(synthesizer, &pub_inputs, &priv_inputs);
        };
    }

    #[test]
    fn test_add() {
        test_op!(add);
        test_op_assign!(add);
    }

    #[test]
    fn test_sub() {
        test_op!(sub);
        test_op_assign!(sub);
    }

    // We cannot use the `test_op` macro for `mul` because
    // `mul` is for some reason a private function in `F`.
    #[test]
    fn test_mul() {
        let synthesizer = |cs: &mut ConstraintSystem<_>| {
            let a = cs.alloc_priv_input();
            let b = cs.alloc_priv_input();

            // a $op b = c
            let c = a * b;

            cs.expose_public(c);
        };

        let a = F::from(3u32);
        let b = F::from(4u32);
        let c = a * b;
        let priv_inputs = [a, b];
        let pub_inputs = [c];
        test_satisfiability(synthesizer, &pub_inputs, &priv_inputs);
    }

    #[test]
    fn test_div() {
        test_op!(div);
        test_op_assign!(div);
    }

    #[test]
    fn test_and() {
        let synthesizer = |cs: &mut ConstraintSystem<_>| {
            let a = cs.alloc_priv_input();
            let b = cs.alloc_priv_input();

            // a AND b = c
            let c = cs.and(a, b);

            cs.expose_public(c);
        };

        let cases = [(false, false), (false, true), (true, false), (true, true)];

        for case in &cases {
            let a = F::from(case.0);
            let b = F::from(case.1);
            let c = F::from(case.0 & case.1);
            let priv_inputs = [a, b];
            let pub_inputs = [c];
            test_var_pub_input(synthesizer, &pub_inputs, &priv_inputs);
        }
    }

    #[test]
    fn test_or() {
        let synthesizer = |cs: &mut ConstraintSystem<_>| {
            let a = cs.alloc_priv_input();
            let b = cs.alloc_priv_input();

            // a AND b = c
            let c = cs.or(a, b);

            cs.expose_public(c);
        };

        let cases = [(false, false), (false, true), (true, false), (true, true)];

        for case in &cases {
            let a = F::from(case.0);
            let b = F::from(case.1);
            let c = F::from(case.0 || case.1);
            let priv_inputs = [a, b];
            let pub_inputs = [c];
            test_var_pub_input(synthesizer, &pub_inputs, &priv_inputs);
        }
    }

    #[test]
    fn test_not() {
        let synthesizer = |cs: &mut ConstraintSystem<_>| {
            let a = cs.alloc_priv_input();

            // a AND b = c
            let c = cs.not(a);

            cs.expose_public(c);
        };

        let cases = [true, false];

        for case in &cases {
            let a = F::from(*case);
            let c = F::from(!case);
            let priv_inputs = [a];
            let pub_inputs = [c];
            test_var_pub_input(synthesizer, &pub_inputs, &priv_inputs);
        }
    }

    #[test]
    fn test_div_or_zero() {
        let synthesizer = |cs: &mut ConstraintSystem<_>| {
            let a = cs.alloc_priv_input();
            let b = cs.alloc_priv_input();

            // a $op b = c
            let c = a.div_or_zero(b);

            cs.expose_public(c);
        };

        // Divide by nonzero

        let a = F::from(3u32);
        let b = F::from(4u32);
        let c = a / b;
        let priv_inputs = [a, b];
        let pub_inputs = [c];
        test_satisfiability(synthesizer, &pub_inputs, &priv_inputs);

        // Divide by 0

        let a = F::from(3u32);
        let b = F::from(0u32);
        let c = F::ZERO;
        let priv_inputs = [a, b];
        let pub_inputs = [c];
        test_var_pub_input(synthesizer, &pub_inputs, &priv_inputs);
    }

    #[test]
    fn test_mul_add() {
        let synthesizer = |cs: &mut ConstraintSystem<_>| {
            // a * b + c = d
            let a = cs.alloc_priv_input();
            let b = cs.alloc_priv_input();
            let c = cs.alloc_priv_input();

            let d = cs.mul_add(a, b, c);
            cs.expose_public(d);
        };

        let a = F::from(3u32);
        let b = F::from(4u32);
        let c = F::from(5u32);
        let d = a * b + c;
        let priv_inputs = [a, b, c];
        let pub_inputs = [d];
        test_satisfiability(synthesizer, &pub_inputs, &priv_inputs);
    }

    #[test]
    fn test_is_equal() {
        let synthesizer = |cs: &mut ConstraintSystem<_>| {
            // a == b = c
            let a = cs.alloc_priv_input();
            let b = cs.alloc_priv_input();

            let c = cs.is_equal(a, b);
            cs.expose_public(c);
        };

        let a = F::from(3u32);
        let b = F::from(4u32);

        let cases = [
            (a, a),
            (a, b),
            (b, a),
            (F::ZERO, a),
            (F::ONE, a),
            (F::ZERO, F::ZERO),
        ];

        for case in &cases {
            let c = F::from(case.0 == case.1);
            let priv_inputs = [case.0, case.1];
            let pub_inputs = [c];
            test_var_pub_input(synthesizer, &pub_inputs, &priv_inputs);
        }
    }

    #[test]
    fn test_is_zero() {
        let synthesizer = |cs: &mut ConstraintSystem<_>| {
            // a == 0 = c
            let a = cs.alloc_priv_input();

            let c = cs.is_zero(a);
            cs.expose_public(c);
        };

        let a = F::from(3u32);
        let cases = [a, F::ZERO];

        for case in &cases {
            let b = F::from(*case == F::ZERO);
            let priv_inputs = [*case];
            let pub_inputs = [b];
            test_var_pub_input(synthesizer, &pub_inputs, &priv_inputs);
        }
    }

    #[test]
    fn test_assert_zero() {
        let synthesizer = |cs: &mut ConstraintSystem<_>| {
            // a == 0 = c
            let a = cs.alloc_priv_input();

            cs.assert_zero(a);
        };

        let priv_inputs = [F::ZERO];
        let pub_inputs = [];
        test_var_pub_input(synthesizer, &pub_inputs, &priv_inputs);

        // TODO: Check that the circuit asserts when the input is not zero
    }

    #[test]
    fn test_conditional() {
        let synthesizer = |cs: &mut ConstraintSystem<_>| {
            let a = cs.alloc_priv_input();
            let b = cs.alloc_priv_input();
            let c = cs.alloc_priv_input();

            let sel1 = cs.alloc_priv_input();
            let sel2 = cs.alloc_priv_input();

            let out = cs.if_then(sel1, a).elif(sel2, b, cs).else_then(c);

            cs.expose_public(out);
        };

        let a = F::from(3);
        let b = F::from(4);
        let c = F::from(5);

        let cases = [(true, true), (true, false), (false, true), (false, false)];

        for case in cases {
            let priv_inputs = [a, b, c, F::from(case.0), F::from(case.1)];
            let out = if case.0 {
                a
            } else if case.1 {
                b
            } else {
                c
            };
            let pub_inputs = [out];
            test_var_pub_input(synthesizer, &pub_inputs, &priv_inputs);
        }
    }
}
