// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console2 as console} from "forge-std/Test.sol";

import {EntryPoint} from "src/core/EntryPoint.sol";
import {IEntryPoint} from "src/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";
import {ValidationData, _packValidationData} from "src/core/Helpers.sol";

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
}

contract RevertsOnEtherReceived {
    receive() external payable {
        revert();
    }
}

contract EntryPointTest is Test {
    EPH private entryPoint;

    function setUp() external {
        entryPoint = new EPH();
    }

    function testIfUserOperationHashIsCorrect() external {
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: makeAddr("random"),
            nonce: 0,
            initCode: hex"023343",
            callData: hex"023343",
            accountGasLimits: bytes32(uint256(1234567890)),
            preVerificationGas: uint256(1234567890),
            gasFees: bytes32(uint256(1234567890)),
            paymasterAndData: hex"023343",
            signature: hex"023343"
        });

        bytes32 expectedUserOpHash = keccak256(
            abi.encode(
                keccak256(
                    abi.encode(
                        userOp.sender,
                        userOp.nonce,
                        keccak256(userOp.initCode),
                        keccak256(userOp.callData),
                        userOp.accountGasLimits,
                        userOp.preVerificationGas,
                        userOp.gasFees,
                        keccak256(userOp.paymasterAndData)
                    )
                ),
                address(entryPoint),
                block.chainid
            )
        );

        bytes32 actualUserOpHash = entryPoint.getUserOpHash(userOp);

        vm.assertEq(actualUserOpHash, expectedUserOpHash);
    }

    function testGetValidationDataReturnsCorrectValue() external {
        uint256 validationData;
        address aggregator;
        bool outOfTimeRange;

        // Case 1: sigFailed = false, default time range
        validationData = _packValidationData(false, 0, 0);
        (aggregator, outOfTimeRange) = entryPoint.expose_getValidationData(validationData);
        vm.assertEq(uint160(aggregator), 0);
        vm.assertFalse(outOfTimeRange);

        // Case 2: sigFailed = true, default time range
        validationData = _packValidationData(true, 0, 0);
        (aggregator, outOfTimeRange) = entryPoint.expose_getValidationData(validationData);
        vm.assertEq(uint160(aggregator), 1);
        vm.assertFalse(outOfTimeRange);

        // Define validation data struct for time-based tests
        ValidationData memory validationDataStruct =
            ValidationData({aggregator: address(0), validAfter: 90, validUntil: 105});

        // Case 3: Time before validAfter (expecting out of time range)
        vm.warp(85);
        validationData = _packValidationData(validationDataStruct);
        (aggregator, outOfTimeRange) = entryPoint.expose_getValidationData(validationData);
        vm.assertEq(uint160(aggregator), 0);
        vm.assertTrue(outOfTimeRange);

        // Case 4: Within valid time range
        vm.warp(100);
        validationData = _packValidationData(validationDataStruct);
        (aggregator, outOfTimeRange) = entryPoint.expose_getValidationData(validationData);
        vm.assertEq(uint160(aggregator), 0);
        vm.assertFalse(outOfTimeRange);

        // Case 5: Time after validUntil (expecting out of time range)
        vm.warp(110);
        validationData = _packValidationData(validationDataStruct);
        (aggregator, outOfTimeRange) = entryPoint.expose_getValidationData(validationData);
        vm.assertEq(uint160(aggregator), 0);
        vm.assertTrue(outOfTimeRange);
    }

    function testValidateAccountAndPaymasterValidationDataRevertsWithCorrectErrors() external {
        uint256 validationData;
        uint256 paymasterValidationData;

        // Case 1: Account validation data has signature error
        validationData = _packValidationData(true, 0, 0);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 1, "AA24 signature error"));
        entryPoint.expose_validateAccountAndPaymasterValidationData(1, validationData, 0, address(0));

        // Case 2: Account validation data is expired or not due
        validationData = _packValidationData(false, 0, 10);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 1, "AA22 expired or not due"));
        entryPoint.expose_validateAccountAndPaymasterValidationData(1, validationData, 0, address(0));

        // Reset account validation data to no error for paymaster tests
        validationData = _packValidationData(false, 0, 0);

        // Case 3: Paymaster validation data has signature error
        paymasterValidationData = _packValidationData(true, 0, 0);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 1, "AA34 signature error"));
        entryPoint.expose_validateAccountAndPaymasterValidationData(
            1, validationData, paymasterValidationData, address(0)
        );

        // Case 4: Paymaster validation data is expired or not due
        paymasterValidationData = _packValidationData(false, 0, 10);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 1, "AA32 paymaster expired or not due"));
        entryPoint.expose_validateAccountAndPaymasterValidationData(
            1, validationData, paymasterValidationData, address(0)
        );
    }

    function testCompensateRevertsOnZeroAddress() external {
        vm.expectRevert("AA90 invalid beneficiary");
        entryPoint.expose_compensate(payable(address(0)), 1 ether);
    }

    function testCompensateRevertsOnCallFailed() external {
        RevertsOnEtherReceived receiver = new RevertsOnEtherReceived();

        vm.deal(address(entryPoint), 1 ether);
        vm.expectRevert("AA91 failed send to beneficiary");
        entryPoint.expose_compensate(payable(address(receiver)), 1 ether);
    }
}
