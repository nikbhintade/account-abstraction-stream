// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console2 as console} from "forge-std/Test.sol";

import {EntryPoint} from "src/core/EntryPoint.sol";
import {BaseAccount} from "src/core/BaseAccount.sol";
import {IEntryPoint} from "src/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";
import {ValidationData, _packValidationData} from "src/core/Helpers.sol";
import {SimpleAccount} from "src/samples/SimpleAccount.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "src/core/Helpers.sol";

contract SimpleAccountRevert is BaseAccount {
    IEntryPoint private s_entryPoint;
    Mode private s_mode;

    enum Mode {
        RevertOnValidate,
        SendLessPreFund
    }

    constructor(IEntryPoint _entryPoint, Mode mode) {
        s_entryPoint = _entryPoint;
        s_mode = mode;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return s_entryPoint;
    }

    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        override
        returns (uint256 validationData)
    {
        (userOp, userOpHash);
        if (s_mode == Mode.RevertOnValidate) {
            revert("Validate Reverted");
        } else {
            return SIG_VALIDATION_SUCCESS;
        }
    }

    function _payPrefund(uint256 missingAccountFunds) internal override {
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{
                value: (s_mode == Mode.SendLessPreFund) ? missingAccountFunds / 2 : missingAccountFunds,
                gas: type(uint256).max
            }("");
            (success);
            //ignore failure (its EntryPoint's job to verify, not account.)
        }
    }
}

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
}

contract RevertsOnEtherReceived {
    receive() external payable {
        revert();
    }
}

contract EntryPointTest is Test {
    EPH private entryPoint;
    SimpleAccount private simpleAccount;

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

    function createMuseropAndUserOpInfo()
        internal
        pure
        returns (EntryPoint.UserOpInfo memory, EntryPoint.MemoryUserOp memory)
    {
        EntryPoint.MemoryUserOp memory mUserOp = EntryPoint.MemoryUserOp({
            sender: address(1),
            nonce: 1,
            verificationGasLimit: 25,
            callGasLimit: 26,
            paymasterVerificationGasLimit: 27,
            paymasterPostOpGasLimit: 28,
            preVerificationGas: 29,
            paymaster: address(2),
            maxFeePerGas: 30,
            maxPriorityFeePerGas: 31
        });

        EntryPoint.UserOpInfo memory userOpInfo = EntryPoint.UserOpInfo({
            mUserOp: mUserOp,
            userOpHash: hex"123456",
            prefund: 32,
            contextOffset: 33,
            preOpGas: 34
        });

        return (userOpInfo, mUserOp);
    }

    function testEmitUserOperationEvent() external {
        (EntryPoint.UserOpInfo memory userOpInfo, EntryPoint.MemoryUserOp memory mUserOp) = createMuseropAndUserOpInfo();

        vm.expectEmit(true, true, true, true, address(entryPoint));
        emit IEntryPoint.UserOperationEvent(
            userOpInfo.userOpHash, mUserOp.sender, mUserOp.paymaster, mUserOp.nonce, true, 1234, 5678
        );
        entryPoint.expose_emitUserOperationEvent(userOpInfo, true, 1234, 5678);
    }

    function testEmitUserOperationPrefundTooLow() external {
        (EntryPoint.UserOpInfo memory userOpInfo, EntryPoint.MemoryUserOp memory mUserOp) = createMuseropAndUserOpInfo();

        vm.expectEmit(true, true, false, true, address(entryPoint));
        emit IEntryPoint.UserOperationPrefundTooLow(userOpInfo.userOpHash, mUserOp.sender, mUserOp.nonce);
        entryPoint.expose_emitPrefundTooLow(userOpInfo);
    }

    function testGetRequiredPrefund() external view {
        (, EntryPoint.MemoryUserOp memory mUserOp) = createMuseropAndUserOpInfo();

        uint256 expectedPrefund = (
            mUserOp.verificationGasLimit + mUserOp.callGasLimit + mUserOp.paymasterVerificationGasLimit
                + mUserOp.paymasterPostOpGasLimit + mUserOp.preVerificationGas
        ) * mUserOp.maxFeePerGas;

        vm.assertEq(entryPoint.expose_getRequiredPrefund(mUserOp), expectedPrefund);
    }

    function testgetUserOpGasPrice() external view {
        (, EntryPoint.MemoryUserOp memory mUserOp) = createMuseropAndUserOpInfo();

        // condition 1: both fee values are same
        mUserOp.maxPriorityFeePerGas = mUserOp.maxFeePerGas;
        vm.assertEq(mUserOp.maxFeePerGas, entryPoint.expose_getUserOpGasPrice(mUserOp));

        // condition 2: maxfeeperfas is lower than priority
        mUserOp.maxPriorityFeePerGas = 500;
        vm.assertEq(mUserOp.maxFeePerGas, entryPoint.expose_getUserOpGasPrice(mUserOp));

        mUserOp.maxFeePerGas = 1000;
        vm.assertEq(mUserOp.maxPriorityFeePerGas + block.basefee, entryPoint.expose_getUserOpGasPrice(mUserOp));
    }

    function createSimpleAccountAndRelatedData(bool changeOwner, bool changeAccount, SimpleAccountRevert.Mode mode)
        internal
        returns (PackedUserOperation memory, EntryPoint.UserOpInfo memory)
    {
        Account memory owner = makeAccount("owner");
        Account memory randomUser = makeAccount("randomUser");

        address simpleAccountAddress = changeAccount
            ? address(new SimpleAccountRevert(entryPoint, mode))
            : address(new SimpleAccount(entryPoint, owner.addr));

        PackedUserOperation memory pUserOp = PackedUserOperation({
            sender: simpleAccountAddress,
            nonce: 0,
            initCode: hex"",
            callData: hex"",
            accountGasLimits: bytes32(uint256(100_000) << 128 | uint256(100_000)),
            preVerificationGas: uint256(100_0000),
            gasFees: bytes32(uint256(50) << 128 | uint256(50)),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(pUserOp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(changeOwner ? owner.key : randomUser.key, userOpHash);

        pUserOp.signature = abi.encodePacked(r, s, v);

        EntryPoint.MemoryUserOp memory mUserOp = EntryPoint.MemoryUserOp({
            sender: simpleAccountAddress,
            nonce: 0,
            verificationGasLimit: 100_000,
            callGasLimit: 100_000,
            paymasterVerificationGasLimit: 100_000,
            paymasterPostOpGasLimit: 100_000,
            preVerificationGas: 100_000,
            paymaster: address(0),
            maxFeePerGas: 30,
            maxPriorityFeePerGas: 30
        });

        EntryPoint.UserOpInfo memory userOpInfo =
            EntryPoint.UserOpInfo({mUserOp: mUserOp, userOpHash: userOpHash, prefund: 0, contextOffset: 0, preOpGas: 0});

        vm.deal(simpleAccountAddress, 1 ether);

        return (pUserOp, userOpInfo);
    }

    function testValidateAccountPrepayment() external {
        // validation successful
        (PackedUserOperation memory userOp, EntryPoint.UserOpInfo memory userOpInfo) =
            createSimpleAccountAndRelatedData(true, false, SimpleAccountRevert.Mode.SendLessPreFund);

        uint256 opIndex = 0;
        uint256 requiredPrefund = 0.1 ether;
        uint256 verificationGasLimit = 100_000;

        uint256 validationData = entryPoint.expose_validateAccountPrepayment(
            opIndex, userOp, userOpInfo, requiredPrefund, verificationGasLimit
        );

        vm.assertEq(address(entryPoint).balance, requiredPrefund);
        vm.assertEq(validationData, SIG_VALIDATION_SUCCESS);

        // validation failed

        (userOp, userOpInfo) = createSimpleAccountAndRelatedData(false, false, SimpleAccountRevert.Mode.SendLessPreFund);

        validationData = entryPoint.expose_validateAccountPrepayment(
            opIndex, userOp, userOpInfo, requiredPrefund, verificationGasLimit
        );

        // entryPoint is receiving the amount twice in same test
        vm.assertEq(address(entryPoint).balance, requiredPrefund * 2);
        vm.assertEq(validationData, SIG_VALIDATION_FAILED);
    }

    function testValidateAccountPrepaymentThrowsCorrectError() external {
        (PackedUserOperation memory userOp, EntryPoint.UserOpInfo memory userOpInfo) =
            createSimpleAccountAndRelatedData(false, true, SimpleAccountRevert.Mode.RevertOnValidate);

        uint256 opIndex = 0;
        uint256 requiredPrefund = 0.1 ether;
        uint256 verificationGasLimit = 50_000;

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                opIndex,
                "AA23 reverted",
                abi.encodeWithSignature("Error(string)", "Validate Reverted")
            )
        );
        entryPoint.expose_validateAccountPrepayment(opIndex, userOp, userOpInfo, requiredPrefund, verificationGasLimit);
    }

    function testValidateAccountPrepaymentRevertOnInsufficientPrefund() external {
        (PackedUserOperation memory userOp, EntryPoint.UserOpInfo memory userOpInfo) =
            createSimpleAccountAndRelatedData(false, true, SimpleAccountRevert.Mode.SendLessPreFund);

        uint256 opIndex = 0;
        uint256 requiredPrefund = 0.1 ether;
        uint256 verificationGasLimit = 50_000;

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, opIndex, "AA21 didn't pay prefund"));
        entryPoint.expose_validateAccountPrepayment(opIndex, userOp, userOpInfo, requiredPrefund, verificationGasLimit);
    }

    function testValidateAccountPrepaymentTakesMissingAccountFundsFromDeposit() external {
        (PackedUserOperation memory userOp, EntryPoint.UserOpInfo memory userOpInfo) =
            createSimpleAccountAndRelatedData(true, false, SimpleAccountRevert.Mode.SendLessPreFund);

        uint256 intialSimpleAccountBalance = userOp.sender.balance;

        entryPoint.depositTo{value: 1 ether}(userOp.sender);

        uint256 opIndex = 0;
        uint256 requiredPrefund = 0.1 ether;
        uint256 verificationGasLimit = 50_000;

        entryPoint.expose_validateAccountPrepayment(opIndex, userOp, userOpInfo, requiredPrefund, verificationGasLimit);

        assertEq(userOp.sender.balance, intialSimpleAccountBalance);
    }

    function sliceBytes(bytes calldata input, uint256 len) public pure returns (bytes memory) {
        return abi.encodePacked(input[:len]);
    }

    function testCopyUserOpToMemory() external {
        bytes memory random52Bytes = this.sliceBytes(abi.encode(keccak256("hello"), keccak256("world")), 52);

        console.log(random52Bytes.length);

        // PackedUserOperation memory userOp = PackedUserOperation({
        //     sender: address(123),
        //     nonce: 0,
        //     initCode: hex"",
        //     callData: hex"",
        //     accountGasLimits: bytes32 (uint256(50_000) << 128 | uint256(40_000)),
        //     preVerificationGas: 50_000,
        //     gasFees: bytes32 (uint256(30) << 128 | uint256(40))
        //     paymasterAndData:
        //     signature:
        // })
    }
}
