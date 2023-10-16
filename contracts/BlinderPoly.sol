// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "./IPA.sol";
import "./FF.sol";

// import "../lib/forge-std/src/console.sol";

contract BlinderPoly is IPA {
    using Fq for uint256;

    constructor() {}

    function verifyOpening(
        EvmInnerProductProof memory proof,
        uint256[] memory x,
        uint256 polyDegree,
        EvmGens memory gens,
        bytes32 state
    ) internal returns (bool) {
        uint256[] memory b = evalPointPowers(polyDegree, x);

        // Resize b to be of length 2^m
        uint256 n = 1 << proof.L.length;
        uint256[] memory bResized = new uint256[](n);
        for (uint256 i = 0; i < b.length; i++) {
            bResized[i] = b[i];
        }

        return IPA.verify(proof, bResized, gens, state);
    }

    function evalPointPowers(
        uint256 polyDegree,
        uint256[] memory x
    ) internal view returns (uint256[] memory) {
        uint256 n = x.length;
        uint256[] memory b = new uint256[](n * (polyDegree + 1));

        for (uint256 i = 0; i < n; i++) {
            uint256[] memory powers = new uint256[](polyDegree + 1);
            uint256 cPow = 1;

            for (uint256 j = 0; j < polyDegree + 1; j++) {
                powers[j] = cPow;
                cPow *= x[i];
            }

            for (uint256 j = 0; j < polyDegree + 1; j++) {
                b[i * (polyDegree + 1) + j] = powers[polyDegree - j];
            }
        }

        return b;
    }
}
