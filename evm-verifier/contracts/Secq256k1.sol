// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

// Uncomment this line to use console.log
import "../lib/forge-std/src/console.sol";
import "./FF.sol";

struct EvmAffinePoint {
    uint256 x;
    uint256 y;
}

struct EvmProjectivePoint {
    uint256 x;
    uint256 y;
    uint256 z;
}

// @dev Secq256k1 operations
contract Secq256k1 {
    using Fp for uint256;

    uint256 public constant A = 0;
    uint256 public constant B = 7;

    constructor() {}

    // Copied from https://github.com/witnet/elliptic-curve-solidity
    /// @dev Modular euclidean inverse of a number (mod p).
    /// @param _x The number
    /// @param _pp The modulus
    /// @return q such that x*q = 1 (mod _pp)
    function invMod(uint256 _x, uint256 _pp) internal pure returns (uint256) {
        require(_x != 0 && _x != _pp && _pp != 0, "Invalid number");
        uint256 q = 0;
        uint256 newT = 1;
        uint256 r = _pp;
        uint256 t;
        while (_x != 0) {
            t = r / _x;
            (q, newT) = (newT, addmod(q, (_pp - mulmod(t, newT, _pp)), _pp));
            (r, _x) = (_x, r - t * _x);
        }

        return q;
    }

    // @dev Convert `EvmAffinePoint` to `EvmProjectivePoint`
    function toProjective(
        EvmAffinePoint memory point
    ) public pure returns (EvmProjectivePoint memory) {
        return EvmProjectivePoint(point.x, point.y, 1);
    }

    // @dev Convert `EvmProjectivePoint` to `EvmAffinePoint`
    function toAffine(
        EvmProjectivePoint memory point
    ) public pure returns (EvmAffinePoint memory) {
        uint256 zInv = invMod(point.z, Fp.MODULUS);

        // Sanity check
        require(point.z.mul(zInv) == 1, "Invalid zInv");

        uint256 x = point.x.mul(zInv);
        uint256 y = point.y.mul(zInv);

        return EvmAffinePoint(x, y);
    }

    // @dev Naive multi-scalar multiplication
    function msm_naive(
        EvmAffinePoint[] memory bases,
        uint256[] memory scalars
    ) public view returns (EvmProjectivePoint memory) {
        require(bases.length == scalars.length, "Length mismatch");
        uint256 accX = 0;
        uint256 accY = 0;
        uint256 accZ = 1;

        uint256 basisZ = 1;
        for (uint256 i = 0; i < bases.length; i++) {
            uint256 scalar = scalars[i];

            (uint256 x, uint256 y, uint256 z) = Secq256k1._mul(
                bases[i].x,
                bases[i].y,
                basisZ,
                scalar
            );

            (accX, accY, accZ) = Secq256k1._add(accX, accY, accZ, x, y, z);
        }

        return EvmProjectivePoint(accX, accY, accZ);
    }

    // @dev Sum the given points
    function sum(
        EvmAffinePoint[] memory points
    ) public returns (EvmProjectivePoint memory) {
        uint256 accX = 0;
        uint256 accY = 0;
        uint256 accZ = 1;

        for (uint256 i = 0; i < points.length; i++) {
            (accX, accY, accZ) = Secq256k1._add(
                accX,
                accY,
                accZ,
                points[i].x,
                points[i].y,
                1
            );
        }

        return EvmProjectivePoint(accX, accY, accZ);
    }

    function _add(
        uint256 p0x,
        uint256 p0y,
        uint256 p0z,
        uint256 p1x,
        uint256 p1y,
        uint256 p1z
    ) internal view returns (uint256, uint256, uint256) {
        if (p0x == 0) {
            return (p1x, p1y, p1z);
        }

        if (p1x == 0) {
            return (p0x, p0y, p0z);
        }

        if (p0x == 0 && p1x == 0) {
            return (0, 0, 1);
        }

        if (p0x == p1x && p0y != p1y) {
            return (0, 0, 1);
        }

        if (p0x == p1x) {
            return double(p0x, p0y, p0z);
        }

        // T_0 = Y_0 * Z_1
        uint256 T_0 = p0y.mul(p1z);

        // T_1 = Y_1 * Z_0
        uint256 T_1 = p1y.mul(p0z);

        // T = T_0 - T_1
        uint256 T = T_0.sub(T_1);

        // U_0 = X_0 * Z_1
        uint256 U_0 = p0x.mul(p1z);

        // U_1 = X_1 * Z_0
        uint256 U_1 = p1x.mul(p0z);

        // U = U_0 - U_1
        uint256 U = U_0.sub(U_1);

        // U_2 =  U * U
        uint256 U_2 = U.mul(U);

        // V = Z_0 * Z_1
        uint256 V = p0z.mul(p1z);

        // W = T^2 * V - U_2 * (U_0 + U_1)
        uint256 W = T.mul(T).mul(V).sub(U_2.mul(U_0.add(U_1)));

        // U_3 = U_2 * U
        uint256 U_3 = U_2.mul(U);

        // X_2 = U * W
        uint256 X_2 = U.mul(W);

        // Y_2 = T * (U_0 * U_2 - W) - U_3 * T_0
        uint256 Y_2 = T.mul(U_0.mul(U_2).sub(W)).sub(U_3.mul(T_0));

        // Z_2 = U_3 * V
        uint256 Z_2 = U_3.mul(V);

        return (X_2, Y_2, Z_2);
    }

    function add(
        EvmProjectivePoint memory p0,
        EvmProjectivePoint memory p1
    ) public view returns (EvmProjectivePoint memory) {
        (uint256 outX, uint256 outY, uint256 outZ) = _add(
            p0.x,
            p0.y,
            p0.z,
            p1.x,
            p1.y,
            p1.z
        );

        return EvmProjectivePoint(outX, outY, outZ);
    }

    function double(
        uint256 x,
        uint256 y,
        uint256 z
    ) public view returns (uint256, uint256, uint256) {
        if (y == 0) {
            return (0, 0, 1);
        }

        //  T = 3 * p.x^2 + a * p.z^2
        // TODO: Could remove the A part since it's zero.
        uint256 T = (uint256(3).mul(x.mul(x))).add(A.mul(z.mul(z)));

        // U = 2 * p.y * p.z
        uint256 U = uint256(2).mul(y.mul(z));

        // V = 2 * U * p.x * p.y
        uint256 V = uint256(2).mul(U.mul(x.mul(y)));

        // W = T^2 - 2V
        uint256 W = T.mul(T).sub(uint256(2).mul(V));

        // UY = U * p.y
        uint256 UY = U.mul(y);

        // UY_SQUARED = UY^2
        uint256 UY_SQUARED = UY.mul(UY);

        // xOut = U * W
        uint256 xOut = U.mul(W);

        // yOut = T(V - W) - 2(UY)^2
        uint256 yOut = T.mul(V.sub(W)).sub(uint256(2).mul(UY_SQUARED));

        // zOut = U^3
        uint256 zOut = U.mul(U).mul(U);

        return (xOut, yOut, zOut);
    }

    function _mul(
        uint256 px,
        uint256 py,
        uint256 pz,
        uint256 scalar
    ) public view returns (uint256, uint256, uint256) {
        // Early return in case that `scalar == 0`
        if (scalar == 0) {
            return (px, py, pz);
        }

        uint256 acc_x = 0;
        uint256 acc_y = 0;
        uint256 acc_z = 1;

        uint256 remaining = scalar;

        while (remaining != 0) {
            if ((remaining & 1) != 0) {
                (acc_x, acc_y, acc_z) = _add(acc_x, acc_y, acc_z, px, py, pz);
            }

            (px, py, pz) = double(px, py, pz);
            remaining = remaining / 2;
        }

        return (acc_x, acc_y, acc_z);
    }

    // Inspired by:
    function mul(
        EvmProjectivePoint memory point,
        uint256 scalar
    ) public view returns (EvmProjectivePoint memory) {
        (uint256 outX, uint256 outY, uint256 outZ) = _mul(
            point.x,
            point.y,
            point.z,
            scalar
        );
        return EvmProjectivePoint(outX, outY, outZ);
    }
}
