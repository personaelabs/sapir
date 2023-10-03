// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "./Hyrax.sol";
import "./FF.sol";
// import "../lib/forge-std/src/console.sol";

struct EvmSumCheckProof {
    // Coefficients of the round polynomials
    uint256[][] roundPolysCoeffs;
    // Sum of the blinder polynomial
    uint256 blindPolySum;
    EvmPolyEvalProof blindPolyEvalProof;
}

contract SumCheck {
    using Fq for uint256;

    constructor() {}

    /**
     * @dev Evaluates the given univariate polynomial at the given point.
     */
    function evalUniPoly(
        uint256[] memory coeffs,
        uint256 x
    ) internal pure returns (uint256) {
        uint256 result = 0;
        uint256 _x = x;
        for (uint256 i = 0; i < coeffs.length; i++) {
            if (i == 0) {
                result = result.add(coeffs[coeffs.length - 1]);
            } else {
                result = result.add(coeffs[coeffs.length - i - 1].mul(x));
                x = x.mul(_x);
            }
        }
        return result;
    }

    /**
     * @dev Verifies the round polynomials and returns the final evaluation.
     */
    function verifyRoundPolys(
        EvmSumCheckProof memory proof,
        uint256 rho,
        uint256[] memory challenge,
        uint256 sumTarget
    ) internal returns (uint256) {
        // Verify the validity of the round polynomials.
        uint256 target = sumTarget.add(rho.mul(proof.blindPolySum));

        for (uint256 i = 0; i < proof.roundPolysCoeffs.length; ) {
            uint256[] memory coeffs = proof.roundPolysCoeffs[i];

            // Evaluation at 0 is the intercept of the polynomial.
            uint256 evalAt0 = coeffs[coeffs.length - 1];

            // Evaluation at 1 is the sum of the coefficients.
            uint256 evalAt1 = 0;
            for (uint256 j = 0; j < coeffs.length; j++) {
                evalAt1 = evalAt1.add(coeffs[j]);
            }

            require(evalAt0.add(evalAt1) == target, "Invalid round polynomial");
            target = evalUniPoly(coeffs, challenge[i]);

            unchecked {
                i++;
            }
        }

        return target;
    }
}
