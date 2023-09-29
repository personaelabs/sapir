// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

// @dev Secq256k1 base field arithmetic
library Fp {
    uint256 public constant MODULUS =
        0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return addmod(a, b, MODULUS);
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a < b) {
            return MODULUS - ((b - a) % MODULUS);
        }
        return (a - b) % MODULUS;
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return mulmod(a, b, MODULUS);
    }
}

// @dev Secq256k1 scalar field arithmetic
library Fq {
    uint256 public constant MODULUS =
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return addmod(a, b, MODULUS);
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a < b) {
            return MODULUS - ((b - a) % MODULUS);
        }
        return (a - b) % MODULUS;
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return mulmod(a, b, MODULUS);
    }
}
