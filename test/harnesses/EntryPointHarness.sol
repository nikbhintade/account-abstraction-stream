// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.24;

import {EntryPoint} from "src/core/EntryPoint.sol";
import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";

//// @title EntryPointHarness Contract
/// @notice This is a harness contract that we are using to expose the internal functions of EntryPoint.sol
contract EPH is EntryPoint {
    function expose_getValidationData(uint256 validationData)
        external
        view
        returns (address aggregator, bool outOfTimeRange)
    {
        return _getValidationData(validationData);
    }

    function expose_validateAccountAndPaymasterValidationData(
        uint256 opIndex,
        uint256 validationData,
        uint256 paymasterValidationData,
        address expectedAggregator
    ) external view {
        return _validateAccountAndPaymasterValidationData(
            opIndex, validationData, paymasterValidationData, expectedAggregator
        );
    }

    function expose_compensate(address payable beneficiary, uint256 amount) external {
        return _compensate(beneficiary, amount);
    }

    function expose_emitUserOperationEvent(
        UserOpInfo memory opInfo,
        bool success,
        uint256 actualGasCost,
        uint256 actualGas
    ) external {
        emitUserOperationEvent(opInfo, success, actualGasCost, actualGas);
    }

    function expose_emitPrefundTooLow(UserOpInfo memory userOpInfo) external {
        emitPrefundTooLow(userOpInfo);
    }

    function expose_getRequiredPrefund(MemoryUserOp memory mUserOp) external pure returns (uint256) {
        return _getRequiredPrefund(mUserOp);
    }

    function expose_getUserOpGasPrice(MemoryUserOp memory mUserOp) external view returns (uint256) {
        return getUserOpGasPrice(mUserOp);
    }

    function expose_copyUserOpToMemory(PackedUserOperation calldata userOp)
        external
        pure
        returns (MemoryUserOp memory)
    {
        MemoryUserOp memory mUserOp;
        _copyUserOpToMemory(userOp, mUserOp);
        return mUserOp;
    }

    function expose_validateAccountPrepayment(
        uint256 opIndex,
        PackedUserOperation calldata op,
        UserOpInfo memory opInfo,
        uint256 requiredPrefund,
        uint256 verificationGasLimit
    ) external returns (uint256 validationData) {
        return _validateAccountPrepayment(opIndex, op, opInfo, requiredPrefund, verificationGasLimit);
    }

    function expose_validatePaymasterPrepayment(
        uint256 opIndex,
        PackedUserOperation calldata op,
        UserOpInfo memory opInfo,
        uint256 requiredPreFund
    ) external returns (bytes memory context, uint256 validationData) {
        return _validatePaymasterPrepayment(opIndex, op, opInfo, requiredPreFund);
    }

    function expose_validatePrepayment(
        uint256 opIndex,
        PackedUserOperation calldata userOp,
        UserOpInfo memory outOpInfo
    ) external returns (uint256 validationData, uint256 paymasterValidationData) {
        return _validatePrepayment(opIndex, userOp, outOpInfo);
    }

    function expose_createSenderIfNeeded(uint256 opIndex, UserOpInfo memory opInfo, bytes calldata initCode) external {
        _createSenderIfNeeded(opIndex, opInfo, initCode);
    }

    function expose_executeUserOp(uint256 opIndex, PackedUserOperation calldata userOp, UserOpInfo memory opInfo)
        external
        returns (uint256 collected)
    {
        return _executeUserOp(opIndex, userOp, opInfo);
    }
}
