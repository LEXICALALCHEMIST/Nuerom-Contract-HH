// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Neurom is EIP712 {
    using ECDSA for bytes32;

    struct Proof {
        string proofId;
        string userId;
        uint256 skeleton;
        string[] morphIds;
    }

    mapping(string => Proof) public proofs;
    mapping(string => bool) public usedProofIds;

    event ProofSubmitted(string proofId, string userId, uint256 skeleton, string[] morphIds);

    constructor() EIP712("NeuromProtocol", "1") {}

    function submitProof(
        Proof memory proof,
        bytes memory signature
    ) external {
        require(!usedProofIds[proof.proofId], "Proof ID already used");

        // Verify EIP-712 signature
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
            keccak256("Proof(string proofId,string userId,uint256 skeleton,string[] morphIds)"),
            keccak256(bytes(proof.proofId)),
            keccak256(bytes(proof.userId)),
            proof.skeleton,
            keccak256(abi.encodePacked(proof.morphIds))
        )));
        address signer = digest.recover(signature);
        require(signer != address(0), "Invalid signature");

        // Store proof
        proofs[proof.proofId] = Proof(
            proof.proofId,
            proof.userId,
            proof.skeleton,
            proof.morphIds
        );
        usedProofIds[proof.proofId] = true;

        emit ProofSubmitted(proof.proofId, proof.userId, proof.skeleton, proof.morphIds);
    }

    function getProof(string memory proofId) external view returns (Proof memory) {
        return proofs[proofId];
    }
}