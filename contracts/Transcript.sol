// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "./Secq256k1.sol";

/**
 * @dev Stil not implemented!!
 */
contract Transcript {
    constructor() {}

    function apepnd_uint256(
        bytes32 state,
        uint256 scalar
    ) internal pure returns (bytes32) {
        // TBD
    }

    function append_point(
        bytes32 state,
        EvmProjectivePoint memory point
    ) internal pure returns (bytes32) {
        // TBD
    }

    function challenge_scalar(bytes32 state) internal pure returns (uint256) {
        // TBD

        // !This is temporary
        return 33;
    }

    function challenge_vec(
        bytes32 state,
        uint256 n
    ) internal pure returns (uint256[] memory) {
        // TBD

        // !This is temporary
        uint256[] memory vec = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            vec[i] = 33;
        }
        return vec;
    }
}
