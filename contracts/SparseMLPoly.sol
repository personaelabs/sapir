// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "./FF.sol";
import "./EqPoly.sol";

struct LagrangeEntry {
    uint256 index;
    uint256 val;
}

contract SparseMLPoly is EqPoly {
    using Fq for uint256;

    constructor() {}

    /**
     * @dev Evaluates the given sparse multilinear polynomial at the given point.
     */
    function eval(
        LagrangeEntry[] memory lagrangePoly,
        uint256[] memory x
    ) public returns (uint256) {
        uint256 result = 0;
        for (uint256 i = 0; i < lagrangePoly.length; i++) {
            uint256 term = EqPoly.evalAsBits(x, lagrangePoly[i].index).mul(
                lagrangePoly[i].val
            );

            result = result.add(term);
        }

        return result;
    }
}
