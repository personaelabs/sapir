// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "./Secq256k1.sol";
import "./Transcript.sol";
import "./FF.sol";
import "../lib/forge-std/src/console.sol";

// Generators for the Pedersen commitment
struct EvmGens {
    EvmAffinePoint[] G;
    EvmAffinePoint H;
    EvmAffinePoint u;
}

// @dev Inner product proof
struct EvmInnerProductProof {
    EvmAffinePoint comm;
    EvmAffinePoint[] L;
    EvmAffinePoint[] R;
    EvmAffinePoint[] sGPowers;
    EvmAffinePoint R_zko;
    uint256 z1;
    uint256 z2;
    uint256 y;
}

contract IPA is Secq256k1, Transcript {
    using Fq for uint256;

    constructor() {}

    function copmuteScalars(
        uint256[] memory r,
        uint256[] memory rInv,
        uint256 n,
        uint256 m
    ) internal pure returns (uint256[] memory) {
        uint256[] memory s = new uint256[](n);

        for (uint256 i = 0; i < n; i++) {
            uint256 s_i = 1;
            for (uint256 j = 0; j < m; j++) {
                if ((i >> j) & 1 == 1) {
                    s_i = s_i.mul(rInv[j]);
                } else {
                    s_i = s_i.mul(r[j]);
                }
            }

            s[i] = s_i;
        }
        return s;
    }

    /**
     * @notice Scales the vector `v` by a scalar `s`.
     */
    function scaleVec(
        uint256[] memory v,
        uint256 s
    ) internal pure returns (uint256[] memory) {
        uint256[] memory scaled = new uint256[](v.length);
        for (uint256 i = 0; i < v.length; i++) {
            scaled[i] = v[i].mul(s);
        }
        return scaled;
    }

    /**
     * @notice Scale elliptic curve points `p` by a scalar `s`.
     */
    function scalePoints(
        EvmProjectivePoint[] memory p,
        uint256 s
    ) internal view returns (EvmProjectivePoint[] memory) {
        EvmProjectivePoint[] memory scaled = new EvmProjectivePoint[](
            p.length * 3
        );
        for (uint256 i = 0; i < p.length; i++) {
            EvmProjectivePoint memory pi = EvmProjectivePoint(
                p[i].x,
                p[i].y,
                p[i].z
            );
            scaled[i] = Secq256k1.mul(pi, s);
        }
        return scaled;
    }

    function fold(
        uint256[] memory a,
        uint256 xLow,
        uint256 xHigh
    ) internal returns (uint256[] memory) {
        uint256 n = a.length;
        uint nHalf = n / 2;

        uint256[] memory folded = new uint256[](nHalf);

        for (uint256 i = 0; i < nHalf; i++) {
            folded[i] = a[i].mul(xLow).add(a[i + nHalf].mul(xHigh));
        }

        return folded;
    }

    /**
     * @dev Verifies an inner product proof.
     */
    function verify(
        EvmInnerProductProof memory proof,
        uint256[] memory b,
        EvmGens memory gens,
        bytes32 state
    ) public returns (bool) {
        uint256 n = b.length;
        uint256 m = proof.L.length;

        // Rescale `u`
        Transcript.apepnd_uint256(state, proof.y);
        uint256 x = Transcript.challenge_scalar(state);
        EvmProjectivePoint memory u = Secq256k1.toProjective(gens.u);
        u = Secq256k1.mul(u, x);

        console.log("n: %s", n);
        console.log("m: %s", m);
        console.log("u.x: %s", u.x);

        uint256[] memory r = Transcript.challenge_vec(state, proof.L.length);
        // Check that the provided rInvs are correct
        uint256[] memory rInv = new uint256[](m);
        for (uint256 i = 0; i < m; i++) {
            rInv[i] = Secq256k1.invMod(r[i], Fq.MODULUS);
        }

        uint256[] memory s = copmuteScalars(r, rInv, n, m);

        // Compute the folded `b`
        uint256[] memory bFolded = b;
        for (uint256 i = 0; i < m; i++) {
            bFolded = fold(bFolded, rInv[i], r[i]);
        }

        uint256 bFinal = bFolded[0];

        console.log("G.len() %s", gens.G.length);
        console.log("s.len() %s", s.length);
        // Compute the folded G
        // EvmProjectivePoint memory G = Secq256k1.msm_naive(gens.G, s);
        EvmProjectivePoint memory G = Secq256k1.sum(proof.sGPowers);

        // Compute Q

        EvmProjectivePoint memory Q = Secq256k1.add(
            Secq256k1.toProjective(proof.comm),
            Secq256k1.mul(u, proof.y)
        );

        uint256[] memory rSquared = new uint256[](m);
        for (uint256 i = 0; i < m; i++) {
            rSquared[i] = r[i].mul(r[i]);
        }

        uint256[] memory rInvSquared = new uint256[](m);
        for (uint256 i = 0; i < m; i++) {
            rInvSquared[i] = rInv[i].mul(rInv[i]);
        }

        EvmProjectivePoint memory Lr = Secq256k1.msm_naive(proof.L, rSquared);

        EvmProjectivePoint memory RrInv = Secq256k1.msm_naive(
            proof.R,
            rInvSquared
        );

        Q = Secq256k1.add(Secq256k1.add(Lr, RrInv), Q);

        // Verify the zero-knowledge opening
        Transcript.append_point(state, Secq256k1.toProjective(proof.R_zko));
        uint256 c = Transcript.challenge_scalar(state);

        // let lhs = (Q * c).into_affine() + proof.R;
        EvmProjectivePoint memory lhs = Secq256k1.add(
            Secq256k1.mul(Q, c),
            Secq256k1.toProjective(proof.R_zko)
        );

        // let rhs = (G + (u * b).into_affine()) * proof.z1 + self.gens.H.unwrap() * proof.z2;
        // rhs = u * b
        EvmProjectivePoint memory rhs = Secq256k1.mul(u, bFinal);
        // rhs = G + (u * b)
        rhs = Secq256k1.add(G, rhs);
        // rhs = (G + (u * b)) * z1
        rhs = Secq256k1.mul(rhs, proof.z1);
        // rhs = (G + (u * b)) * z1 + H * z2
        rhs = Secq256k1.add(
            rhs,
            Secq256k1.mul(Secq256k1.toProjective(gens.H), proof.z2)
        );

        EvmAffinePoint memory lhsAffine = Secq256k1.toAffine(lhs);
        EvmAffinePoint memory rhsAffine = Secq256k1.toAffine(rhs);

        console.log("lhs.x: %s", lhsAffine.x);
        console.log("lhs.y: %s", lhsAffine.y);
        console.log("rhs.x: %s", rhsAffine.x);
        console.log("rhs.y: %s", rhsAffine.y);

        require(
            lhsAffine.x == rhsAffine.x && lhsAffine.y == rhsAffine.y,
            "Inner product equality check failed"
        );

        /*
        // TODO: Add MSM term checks
        EvmProjectivePoint memory s_G = Secq256k1.sum(proof.sGPowers);

        // P = T_prime + bH + u * proof.y
        EvmProjectivePoint memory P = Secq256k1.add(
            Secq256k1.add(Secq256k1.toProjective(proof.comm), bH),
            Secq256k1.mul(Secq256k1.toProjective(gens.u), proof.y)
        );

        uint256[] memory rSquared = new uint256[](m);
        for (uint256 i = 0; i < m; i++) {
            rSquared[i] = r[i].mul(r[i]);
        }

        uint256[] memory rInvSquared = new uint256[](m);
        for (uint256 i = 0; i < m; i++) {
            rInvSquared[i] = rInv[i].mul(rInv[i]);
        }

        EvmProjectivePoint memory Lr = Secq256k1.msm_naive(proof.L, rSquared);

        EvmProjectivePoint memory RrInv = Secq256k1.msm_naive(
            proof.R,
            rInvSquared
        );

        EvmProjectivePoint memory rhs = Secq256k1.add(
            Secq256k1.add(Lr, RrInv),
            P
        );

        EvmAffinePoint memory lhsAffine = Secq256k1.toAffine(lhs);
        EvmAffinePoint memory rhsAffine = Secq256k1.toAffine(rhs);

        require(
            lhsAffine.x == rhsAffine.x && lhsAffine.y == rhsAffine.y,
            "Inner product equality check failed"
        );
        */

        return true;
    }
}
