// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "./FF.sol";

contract EqPoly {
    using Fq for uint256;

    constructor() {}

    /**
     * @dev Evaluates the given eq(x, e) polynomial at the given point.
     */
    function eval(
        uint256[] memory r,
        uint256[] memory x
    ) public returns (uint256) {
        require(r.length == x.length, "r and x must have the same length");

        uint256 result = 1;
        uint256 one = 1;
        for (uint256 i = 0; i < r.length; i++) {
            // term = (r[i] * x[i] + (1 - r[i]) * (1 - x[i]))
            uint256 term = r[i].mul(x[i]).add(one.sub(r[i]).mul(one.sub(x[i])));

            result = result.mul(term);
        }

        return result;
    }

    // @dev Evaluates the given eq(x, e) polynomial over the boolean hypercube.
    function evals(uint256[] memory t) public pure returns (uint256[] memory) {
        uint256 ell = t.length;
        uint256 numEvals = 2 ** ell;

        uint256[] memory _evals = new uint256[](numEvals);
        for (uint256 i = 0; i < numEvals; i++) {
            _evals[i] = 1;
        }

        uint256 size = 1;

        for (uint256 j = 0; j < ell; ) {
            // in each iteration, we double the size of chis
            size *= 2;
            for (uint256 i = (size - 1); i > 0; ) {
                // copy each element from the prior iteration twice
                uint256 scalar = _evals[i / 2];
                _evals[i] = scalar.mul(t[j]);
                _evals[i - 1] = scalar.sub(_evals[i]);

                if (i == 1) {
                    break;
                }
                unchecked {
                    i -= 2;
                }
            }

            unchecked {
                j++;
            }
        }

        return _evals;
    }

    function evalAsBits(
        uint256[] memory r,
        uint256 x
    ) public returns (uint256) {
        uint256 result = 1;
        uint256 one = 1;
        uint256 m = r.length;

        for (uint256 i = 0; i < m; i++) {
            uint256 bit = (x >> i) & 1;
            uint256 term;
            if (bit == 1) {
                term = r[m - i - 1];
            } else {
                term = one.sub(r[m - i - 1]);
            }

            result = result.mul(term);
        }

        return result;
    }
}
