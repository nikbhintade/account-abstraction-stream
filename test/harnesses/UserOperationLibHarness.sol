// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.24;

import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "src/core/UserOperationLib.sol";

contract UserOperationLibHarness {
    function getSender(PackedUserOperation calldata userOp) external pure returns (address) {
        return UserOperationLib.getSender(userOp);
    }

    function gasPrice(PackedUserOperation calldata userOp) external view returns (uint256) {
        return UserOperationLib.gasPrice(userOp);
    }

    function encode(PackedUserOperation calldata userOp) external pure returns (bytes memory) {
        return UserOperationLib.encode(userOp);
    }

    function unpackMaxPriorityFeePerGas(PackedUserOperation calldata userOp) external pure returns (uint256) {
        return UserOperationLib.unpackMaxPriorityFeePerGas(userOp);
    }

    function unpackMaxFeePerGas(PackedUserOperation calldata userOp) external pure returns (uint256) {
        return UserOperationLib.unpackMaxFeePerGas(userOp);
    }

    function unpackVerificationGasLimit(PackedUserOperation calldata userOp) external pure returns (uint256) {
        return UserOperationLib.unpackVerificationGasLimit(userOp);
    }

    function unpackCallGasLimit(PackedUserOperation calldata userOp) external pure returns (uint256) {
        return UserOperationLib.unpackCallGasLimit(userOp);
    }

    function unpackPaymasterVerificationGasLimit(PackedUserOperation calldata userOp) external pure returns (uint256) {
        return UserOperationLib.unpackPaymasterVerificationGasLimit(userOp);
    }

    function unpackPostOpGasLimit(PackedUserOperation calldata userOp) external pure returns (uint256) {
        return UserOperationLib.unpackPostOpGasLimit(userOp);
    }

    function unpackPaymasterStaticFields(bytes calldata paymasterAndData)
        external
        pure
        returns (address, uint256, uint256)
    {
        return UserOperationLib.unpackPaymasterStaticFields(paymasterAndData);
    }

    function hash(PackedUserOperation calldata userOp) external pure returns (bytes32) {
        return UserOperationLib.hash(userOp);
    }
}
