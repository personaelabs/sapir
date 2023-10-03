// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "./SumCheck.sol";
import "./SparseMLPoly.sol";
import "./IPA.sol";
import "./Hyrax.sol";
import "./EqPoly.sol";
import "../lib/forge-std/src/console.sol";
import "./Transcript.sol";

// Store the A, B, C matrices as multilinear polynomials
struct EvmR1CS {
    LagrangeEntry[] A;
    LagrangeEntry[] B;
    LagrangeEntry[] C;
    uint256 zLen; // Length of the `Z` vector
}

struct FullProof {
    // Phase 1 sumcheck proof
    EvmSumCheckProof scProof1;
    // Phase 2 sumcheck proof
    EvmSumCheckProof scProof2;
    // Evaluation proof of the Z polynomial
    EvmPolyEvalProof zEvalProof;
    uint256 vA;
    uint256 vB;
    uint256 vC;
    uint256[] publicInput;
}

/**
 * @dev
 * Verification step.
 * This is used to specify which part of the proof to verify.
 */
enum VStep {
    SC1BlinderOpening,
    SC2BlinderOpening,
    WitnessOpening,
    MatrixAEval,
    MatrixBEval,
    MatrixCEval
}

contract SpartanVerifier is SumCheck, SparseMLPoly, Hyrax {
    using Fq for uint256;

    constructor() {}

    mapping(bytes32 => bool) public proofs;

    // @dev Check that the proof has not been invalidated yet.
    function assertNotInvalidated(bytes32 proofHash) public {
        require(
            proofs[proofHash] == false,
            "Proof has already been invalidated"
        );
    }

    // @dev Hash `FullProof`
    function hashProof(
        FullProof memory fullProof
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(fullProof));
    }

    function addCircuit(EvmR1CS calldata r1cs) external {
        // Store the hash of the R1CS matrices
        // TBD
    }

    function newStake() public payable {
        // TBD
    }

    /**
     * @notice Submit a proof.
     * This only stores the proof hash, and does not verify the proof.
     */
    function submitProof(
        FullProof calldata fullProof
    ) public returns (bytes32) {
        bytes32 proofHash = hashProof(fullProof);
        console.log("Proof submitted");
        proofs[proofHash] = true;
        return 0;
    }

    /**
     * @notice Verify the proof
     */
    function verifyProof(
        FullProof calldata fullProof,
        EvmR1CS calldata r1cs,
        VStep step,
        OpeningVerifyAuxilaries calldata auxilaries,
        EvmGens calldata gens
    ) public returns (bool) {
        console.log("Verifying proof");
        bytes32 proofHash = hashProof(fullProof);

        // Check if the proof exists and has not been invalided yet.
        require(proofs[proofHash] == true, "Proof does not exist");

        uint256 num_vars = fullProof.scProof1.roundPolysCoeffs.length;

        // Specify which part of the proof the verify.
        bytes32 state = 0;
        // state = apepnd_uint256(state, fullProof.zEvalProof.comm);

        uint256[] memory tau = challenge_vec(state, num_vars);

        // Verify phase 1 sum check

        uint256 rhoSc1 = 33;
        EvmSumCheckProof memory scProof1 = fullProof.scProof1;
        uint256[] memory rx = challenge_vec(state, num_vars);

        uint256 phase1SumTarget = 0;
        uint256 scPhase1Eval = verifyRoundPolys(
            fullProof.scProof1,
            rhoSc1,
            rx,
            phase1SumTarget
        );

        // Verify the opening of the blinder polynomial
        // TODO: Check that the auxiliary information is provided
        Hyrax.verify(scProof1.blindPolyEvalProof, rx, auxilaries, gens, state);

        // Verify the final evaluation
        uint256 eqTauEval = EqPoly.eval(rx, tau);
        uint256 expectedScPhase1Eval = fullProof
            .vA
            .mul(fullProof.vB)
            .sub(fullProof.vC)
            .mul(eqTauEval);

        // Add the blinder polynomial evaluation
        expectedScPhase1Eval = expectedScPhase1Eval.add(
            rhoSc1.mul(scProof1.blindPolyEvalProof.y)
        );

        require(
            expectedScPhase1Eval == scPhase1Eval,
            "Phase 1 sum check eval does not match"
        );

        // Verify phase 2 sum check

        uint256[] memory r = challenge_vec(state, 3);
        uint256 rA = r[0];
        uint256 rB = r[1];
        uint256 rC = r[2];

        uint256 vA = fullProof.vA;
        uint256 vB = fullProof.vB;
        uint256 vC = fullProof.vC;

        uint256 rA_vA = rA.mul(vA);
        uint256 rB_vB = rB.mul(vB);
        uint256 rC_vC = rC.mul(vC);
        uint256 scPhase2SumTarget = rA_vA.add(rB_vB).add(rC_vC);

        uint256 rhoSc2 = 33;
        EvmSumCheckProof memory scProof2 = fullProof.scProof2;
        uint256[] memory ry = challenge_vec(
            state,
            scProof1.roundPolysCoeffs.length
        );

        uint256 scPhase2FinalEval = verifyRoundPolys(
            scProof2,
            rhoSc2,
            ry,
            scPhase2SumTarget
        );

        // Verify the opening of the blinder polynomial
        Hyrax.verify(scProof1.blindPolyEvalProof, rx, auxilaries, gens, state);

        // Concatinate rx and ry
        uint256[] memory rxry = new uint256[](rx.length + ry.length);
        for (uint256 i = 0; i < rx.length; i++) {
            rxry[i] = rx[i];
        }
        for (uint256 i = 0; i < ry.length; i++) {
            rxry[i + rx.length] = ry[i];
        }

        uint256 A_eval = SparseMLPoly.eval(r1cs.A, rxry);
        uint256 B_eval = SparseMLPoly.eval(r1cs.B, rxry);
        uint256 C_eval = SparseMLPoly.eval(r1cs.C, rxry);

        // Construct the input polynomial
        LagrangeEntry[] memory inputPoly = new LagrangeEntry[](
            fullProof.publicInput.length + 1
        );
        inputPoly[0] = LagrangeEntry(0, 1);
        for (uint256 i = 0; i < fullProof.publicInput.length; i++) {
            inputPoly[i + 1] = LagrangeEntry(i + 1, fullProof.publicInput[i]);
        }

        // Evaluate the input polynomial
        uint[] memory ry_sliced = new uint[](ry.length - 1);
        for (uint i = 0; i < ry.length - 1; i++) {
            ry_sliced[i] = ry[i + 1];
        }

        uint256 inputPolyEval = SparseMLPoly.eval(inputPoly, ry_sliced);

        // Get the evaluation of Z(X)
        uint256 zEval = uint256(1).sub(ry[0]).mul(inputPolyEval).add(
            ry[0].mul(fullProof.zEvalProof.y)
        );

        uint256 rA_A_eval = rA.mul(A_eval);
        uint256 rB_B_eval = rB.mul(B_eval);
        uint256 rC_C_eval = rC.mul(C_eval);

        uint256 expectedFinalEval = rA_A_eval.add(rB_B_eval).add(rC_C_eval).mul(
            zEval
        );

        // Add the blinder polynomial evaluation
        expectedFinalEval = expectedFinalEval.add(
            rhoSc2.mul(scProof2.blindPolyEvalProof.y)
        );

        require(
            expectedFinalEval == scPhase2FinalEval,
            "Final eval does not match"
        );

        // Verify the witness polynomial opening
        Hyrax.verify(scProof1.blindPolyEvalProof, rx, auxilaries, gens, state);

        return true;
    }
}
