# Sapir

Sapir is an opinionated Rust library for generating client-side zero-knowledge proofs.

## Features

- Spartan prover.
- R1CS
    - Set of APIs to write R1CS in Rust.
    - Common operations in [gadgets/](https://www.notion.so/src/frontend/gadgets).
- Client-side constraints generation
    - This alleviates the need to download a larger circuit file over the internet.
- Helper macros to compile circuit/prover into wasm.

<aside>
❗ Sapir is unaudited, use at your own risk!

</aside>

## Write your first circuit

*This doc assumes that the reader is familiar with the concept of writing circuits. Prior experience with Circom, ZokRates, Halo2, etc is preferable.*

### 1. Create a new directory

```jsx
mkdir hello-sapir && cd hello-sapir

```

### 2. Initialize a Rust project

```jsx
cargo init --lib

```

### 3. Write the synthesizer

In Sapir, you write a _**synthesizer**_ to define the rules. The following is a synthesizer for a circuit that takes two private inputs and multiplies them.

```rust
fn my_synthesizer<F: Field>(cs: &mut ConstraintSystem<F>) {
    let a = cs.alloc_priv_input();
    let b = cs.alloc_priv_input();

    let c = a * b;

    cs.expose_public(c);
}
```

Let's breakdown the above code.

A synthesizer should have the follwoing function signature.
```jsx
fn my_synthesizer<F: Field>(cs: &mut ConstraintSystem<F>)
```
- `F: Field` This is the finite field which the circuit is defined over.
- `cs: &mut ConstraintSystem<F>` We define the constraints by modifying this.

Next, we allocate two private inputs `a` and `b`, and constraint `c` to be the result of multiplying `a` and `b`.
```jsx
let a = cs.alloc_priv_input();
let b = cs.alloc_priv_input();

let c = a * b;
```


Lastly, we expose `c` as a public input.
```jsx
cs.expose_public(c);
```
### 4. Generate the witness

Now we can generate the witness of our circuit. We use the `Circuit` struct to do so. A Sapir circuit can be instantiated on any elliptic curve that is available in the [arkworks](https://github.com/arkworks-rs/algebra) ecosystem. For this example, we use the secq256k1 curve.

First, add `ark-secq256k1` as a dependency.

```
cargo add ark-secq256k1
```

Next, paste the following code in the same file as you defined `my_synthesizer`.

```jsx
use ark_secq256k1::Fr;
use sapir::frontend::circuit::Circuit;

#[test]
fn test_witness_gen() {
    let mut circuit = Circuit::new(my_synthesizer);
    let pub_inputs = vec![Fr::from(6u32)];
    let priv_inputs = vec![Fr::from(2u32), Fr::from(3u32)];
    let witness = circuit.gen_witness(&pub_inputs, &priv_inputs);

    assert!(circuit.is_sat(&witness, &pub_inputs));
}
```

The above code defines a test that

1. Instantiates `Circuit` with `my_synthesizer`
2. Generates the witness
3. Checks that the witness satisfies the circuit

Run `cargo test` . If the test passes, you have successfully generated a satisfying witness!

### 5. Generating a proof

Now that we have our witness, we can generate a zero-knowledge proof.

Paste the following code and run  `cargo test —tests test_prove`

```rust
use sapir::spartan::spartan::Spartan;
type Curve = ark_secq256k1::Projective;

#[test]
fn test_prove() {
    let mut circuit = Circuit::new(my_synthesizer);
    let pub_inputs = vec![Fr::from(6u32)];
    let priv_inputs = vec![Fr::from(2u32), Fr::from(3u32)];
    let witness = circuit.gen_witness(&pub_inputs, &priv_inputs);

    let r1cs = circuit.to_r1cs();
    let spartan = Spartan::<Curve>::new(b"hello-sapir", r1cs);
    // Generate a proof
    let (proof, _) = spartan.prove(&witness, &pub_inputs);

    // Verify the proof
    spartan.verify(&proof, false);
}
```

### 6. Compile the circuit and the prover to wasm

You can use [wasm-pack](https://rustwasm.github.io/wasm-pack/) to compile the circuit and the prover into wasm.
Install wasm-pack with the following command,
```
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```
and add the following to your `Cargo.toml` 
```jsx
[lib]
crate-type = ["cdylib", "rlib"]
```

Sapir provides a helper macro `embed_to_wasm` which generates code that embeds the circuit and the prover to the compiled wasm file.

Paste the following code and run `wasm-pack build`

```jsx
use sapir::embed_to_wasm;
use sapir::wasm::prelude::*;

type Curve = ark_secq256k1::Projective;
const DOMAIN_STR: &[u8] = b"hello-sapir";

embed_to_wasm!(my_synthesizer, Curve, DOMAIN_STR);
```

wasm-pack generates a `pkg` module that you can import in a JavaScript file.  You can find an example of this at https://github.com/personaelabs/sapir-example.
