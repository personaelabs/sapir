// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "./Secq256k1.sol";
import "./IPA.sol";
import "./EqPoly.sol";

// @dev Hyrax evaluation proof
struct EvmPolyEvalProof {
    EvmAffinePoint[] T;
    uint256 y;
    EvmAffinePoint[] TLpowers; // Powers of T * L to assist the verifier
    EvmInnerProductProof ipProof;
}

enum OpeningVStep {
    tLMSM,
    saGMSM,
    sbGMSM,
    bhMSM
}

struct OpeningVerifyAuxilaries {
    uint256 msmIndex;
    OpeningVStep step;
}

contract Hyrax is IPA, EqPoly {
    constructor() {}

    /**
     * @dev Verifies a Hyrax proof
     * TODO: Allow specifying the step to verify
     */
    function verify(
        EvmPolyEvalProof memory proof,
        uint256[] memory _x,
        EvmGens memory gens,
        bytes32 state
    ) public returns (bool) {
        uint256 padded_x_len;
        if (_x.length & 1 == 1) {
            padded_x_len = (_x.length + 1);
        } else {
            padded_x_len = _x.length;
        }

        uint256 m = padded_x_len / 2;

        // pad x
        uint256[] memory x = new uint256[](padded_x_len);
        for (uint256 i = 0; i < padded_x_len - _x.length; i++) {
            x[i] = 0;
        }
        for (uint256 i = padded_x_len - _x.length; i < padded_x_len; i++) {
            x[i] = _x[i - (padded_x_len - _x.length)];
        }

        uint256[] memory xLow = new uint256[](m);
        uint256[] memory xHigh = new uint256[](m);

        for (uint256 i = 0; i < m; i++) {
            xLow[i] = x[i];
            xHigh[i] = x[i + m];
        }

        uint256[] memory L = EqPoly.evals(xLow);
        uint256[] memory R = EqPoly.evals(xHigh);

        // Compute T_prime
        // EvmProjectivePoint memory T_prime = Secq256k1.msm_naive(proof.T, L);
        EvmProjectivePoint memory T_prime = Secq256k1.sum(proof.TLpowers);

        EvmAffinePoint memory T_prime_affine = Secq256k1.toAffine(T_prime);
        // Check taht T_prime matches
        require(
            T_prime_affine.x == proof.ipProof.comm.x &&
                T_prime_affine.y == proof.ipProof.comm.y,
            "T_prime does not match"
        );

        IPA.verify(proof.ipProof, R, gens, state);

        return true;
    }
}
