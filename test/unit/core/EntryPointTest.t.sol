// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console2 as console} from "forge-std/Test.sol";

import {EntryPoint} from "src/core/EntryPoint.sol";
import {BaseAccount} from "src/core/BaseAccount.sol";
import {IEntryPoint} from "src/interfaces/IEntryPoint.sol";
import {IStakeManager} from "src/interfaces/IStakeManager.sol";
import {INonceManager} from "src/interfaces/INonceManager.sol";
import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";
import {ValidationData, _packValidationData} from "src/core/Helpers.sol";
import {SimpleAccount} from "src/samples/SimpleAccount.sol";
import {AccountFactory} from "src/samples/AccountFactory.sol";
import {Paymaster} from "src/samples/Paymaster.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "src/core/Helpers.sol";
import {EmptySenderFactory} from "test/mock/EmptySenderFactory.sol";

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

    function failExecute() public pure {
        revert();
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

    /*//////////////////////////////////////////////////////////////
                          TESTS GETUSEROPHASH
    //////////////////////////////////////////////////////////////*/
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

    /*//////////////////////////////////////////////////////////////
                        TESTS _GETVALIDATIONDATA
    //////////////////////////////////////////////////////////////*/
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

    /*//////////////////////////////////////////////////////////////
                           TESTS _COMPENSATE
    //////////////////////////////////////////////////////////////*/
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

    /*//////////////////////////////////////////////////////////////
         HELPER FUNCTION TO GENERATE USEROPINFO & MEMORYUSEROP
    //////////////////////////////////////////////////////////////*/

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

    /*//////////////////////////////////////////////////////////////
           TESTS _EMITUSEROPERATIONEVENT & _EMITPREFUNDTOOLOW
    //////////////////////////////////////////////////////////////*/
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

    /*//////////////////////////////////////////////////////////////
                       TESTS _GETREQUIREDPREFUND
    //////////////////////////////////////////////////////////////*/
    function testGetRequiredPrefund() external view {
        (, EntryPoint.MemoryUserOp memory mUserOp) = createMuseropAndUserOpInfo();

        uint256 expectedPrefund = (
            mUserOp.verificationGasLimit + mUserOp.callGasLimit + mUserOp.paymasterVerificationGasLimit
                + mUserOp.paymasterPostOpGasLimit + mUserOp.preVerificationGas
        ) * mUserOp.maxFeePerGas;

        vm.assertEq(entryPoint.expose_getRequiredPrefund(mUserOp), expectedPrefund);
    }

    /*//////////////////////////////////////////////////////////////
                        TESTS _GETUSEROPGASPRICE
    //////////////////////////////////////////////////////////////*/
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

    /*//////////////////////////////////////////////////////////////
      HELPER FUNCTION TO GENERATE PACKEDUSEROPERATION & USEROPINFO
    //////////////////////////////////////////////////////////////*/
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

    /*//////////////////////////////////////////////////////////////
                    TESTS _VALIDATEACCOUNTPREPAYMENT
    //////////////////////////////////////////////////////////////*/

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

    /*//////////////////////////////////////////////////////////////
                       TESTS _COPYUSEROPTOMEMORY
    //////////////////////////////////////////////////////////////*/

    function sliceBytes(bytes calldata input, uint256 len) public pure returns (bytes memory) {
        return abi.encodePacked(input[:len]);
    }

    function testCopyUserOpToMemory() external view {
        bytes memory paymasterAndData = abi.encodePacked(address(1234), uint128(50_000), uint128(60_000)); // paymaster address, pasymasterverificationgaslimt, paymasterpostopgaslimit

        console.log(paymasterAndData.length);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(123),
            nonce: 0,
            initCode: hex"",
            callData: hex"",
            accountGasLimits: bytes32(uint256(50_000) << 128 | uint256(40_000)), //verificationGasLimit, callGasLimit
            preVerificationGas: 50_000,
            gasFees: bytes32(uint256(30) << 128 | uint256(40)), // maxPriorityFeePerGas, maxFeePerGas
            paymasterAndData: paymasterAndData,
            signature: hex""
        });

        EntryPoint.MemoryUserOp memory mUserOp = entryPoint.expose_copyUserOpToMemory(userOp);

        assertEq(mUserOp.verificationGasLimit, 50_000);
        assertEq(mUserOp.callGasLimit, 40_000);

        assertEq(mUserOp.paymasterVerificationGasLimit, 50_000);
        assertEq(mUserOp.paymasterPostOpGasLimit, 60_000);
        assertEq(mUserOp.paymaster, address(1234));
        assertEq(mUserOp.maxPriorityFeePerGas, 30);
        assertEq(mUserOp.maxFeePerGas, 40);
    }

    function testCopyUserOpToMemoryReverts() external {
        bytes memory paymasterAndData = abi.encodePacked(address(1234), uint128(50_000), uint128(60_000)); // paymaster address, pasymasterverificationgaslimt, paymasterpostopgaslimit

        paymasterAndData = this.sliceBytes(paymasterAndData, 51);

        console.log(paymasterAndData.length);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(123),
            nonce: 0,
            initCode: hex"",
            callData: hex"",
            accountGasLimits: bytes32(uint256(50_000) << 128 | uint256(40_000)), //verificationGasLimit, callGasLimit
            preVerificationGas: 50_000,
            gasFees: bytes32(uint256(30) << 128 | uint256(40)), // maxPriorityFeePerGas, maxFeePerGas
            paymasterAndData: paymasterAndData,
            signature: hex""
        });

        vm.expectRevert("AA93 invalid paymasterAndData");
        entryPoint.expose_copyUserOpToMemory(userOp);
    }

    /*//////////////////////////////////////////////////////////////
                 TESTS FOR PAYMASTER RELATED FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    address private sender;
    Paymaster private paymaster;

    function createPUserOpAndUserOpInfo(uint128 paymasterVerificationGas)
        internal
        returns (PackedUserOperation memory userOp, EntryPoint.UserOpInfo memory userOpInfo)
    {
        sender = makeAddr("sender");
        paymaster = new Paymaster(entryPoint);

        userOp = PackedUserOperation({
            sender: sender,
            nonce: 0,
            initCode: hex"",
            callData: hex"",
            accountGasLimits: hex"",
            preVerificationGas: 0,
            gasFees: hex"",
            paymasterAndData: abi.encodePacked(address(paymaster), paymasterVerificationGas, uint128(0)),
            signature: hex""
        });

        // question: should I use exposed function from harness contract to created some conditions for other functions?
        userOpInfo.mUserOp = entryPoint.expose_copyUserOpToMemory(userOp);

        userOpInfo.userOpHash = entryPoint.getUserOpHash(userOp);
    }

    function testPaymasterPrepaymentIsSuccessful() external {
        uint256 requiredPreFund = 0.1 ether;

        (PackedUserOperation memory userOp, EntryPoint.UserOpInfo memory userOpInfo) =
            createPUserOpAndUserOpInfo(100_000);

        entryPoint.depositTo{value: 1 ether}(address(paymaster));

        (bytes memory context, uint256 validationData) =
            entryPoint.expose_validatePaymasterPrepayment(0, userOp, userOpInfo, requiredPreFund);

        vm.assertEq(context, hex"");
        vm.assertEq(validationData, SIG_VALIDATION_FAILED);
    }

    function testPaymasterPrepaymentRevertsOnLowDeposit() external {
        uint256 requiredPreFund = 0.1 ether;
        uint256 opIndex = 0;

        (PackedUserOperation memory userOp, EntryPoint.UserOpInfo memory userOpInfo) =
            createPUserOpAndUserOpInfo(100_000);

        vm.expectRevert(
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, opIndex, "AA31 paymaster deposit too low")
        );
        entryPoint.expose_validatePaymasterPrepayment(opIndex, userOp, userOpInfo, requiredPreFund);
    }

    function testPaymasterPrepaymentRevertsOnLowVerificationLimit() external {
        uint256 requiredPreFund = 0.1 ether;
        uint256 opIndex = 0;

        (PackedUserOperation memory userOp, EntryPoint.UserOpInfo memory userOpInfo) =
            createPUserOpAndUserOpInfo(10_000);

        entryPoint.depositTo{value: 1 ether}(address(paymaster));

        vm.expectRevert(
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, opIndex, "AA36 over paymasterVerificationGasLimit")
        );

        entryPoint.expose_validatePaymasterPrepayment(opIndex, userOp, userOpInfo, requiredPreFund);
    }

    function testPaymasterPrepaymentRevertsWithFailedOpWithRevertError() external {
        uint256 requiredPreFund = 0.1 ether;
        uint256 opIndex = 0;

        (PackedUserOperation memory userOp, EntryPoint.UserOpInfo memory userOpInfo) = createPUserOpAndUserOpInfo(10);

        entryPoint.depositTo{value: 1 ether}(address(paymaster));

        vm.expectRevert(
            abi.encodeWithSelector(IEntryPoint.FailedOpWithRevert.selector, opIndex, "AA33 reverted", hex"")
        );

        entryPoint.expose_validatePaymasterPrepayment(opIndex, userOp, userOpInfo, requiredPreFund);
    }

    // gas overflow test
    // wrong nonce
    // over the gas limit for verification - verificationGasLimit
    // success test with - paymaster & simpleAccount
    // if values in outOpInfo are set correctly

    uint256 callGasLimitsForPrepaymentTest;

    uint256 preVerificationGasForPrepaymentTest;

    uint256 maxFeesPerGasForPrepaymentTest;
    uint256 maxPriorityFeesPerGasForPrepaymentTest;

    function createPackedUserOperationForPrepaymentValidationTest(uint256 verificationGasLimit, uint256 nonce)
        internal
        returns (PackedUserOperation memory userOp)
    {
        callGasLimitsForPrepaymentTest = 20_000;

        preVerificationGasForPrepaymentTest = 30_000;

        maxFeesPerGasForPrepaymentTest = 30;
        maxPriorityFeesPerGasForPrepaymentTest = 10;

        Account memory owner = makeAccount("owner");

        SimpleAccount simpleAccountForPrepaymentTest = new SimpleAccount(entryPoint, owner.addr);
        Paymaster paymasterForPrepaymentTest = new Paymaster(entryPoint);

        paymasterForPrepaymentTest.addAddressToWhitelist(address(simpleAccountForPrepaymentTest));

        userOp = PackedUserOperation({
            sender: address(simpleAccountForPrepaymentTest),
            nonce: nonce,
            initCode: hex"",
            callData: hex"",
            accountGasLimits: bytes32(
                abi.encodePacked(uint128(verificationGasLimit), uint128(callGasLimitsForPrepaymentTest))
            ),
            preVerificationGas: preVerificationGasForPrepaymentTest,
            gasFees: bytes32(maxPriorityFeesPerGasForPrepaymentTest << 128 | maxFeesPerGasForPrepaymentTest),
            paymasterAndData: abi.encodePacked(address(paymasterForPrepaymentTest), uint128(15_000), uint128(17_000)),
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.key, userOpHash);

        userOp.signature = abi.encodePacked(r, s, v);
    }

    /*//////////////////////////////////////////////////////////////
                               TEST NONCE
    //////////////////////////////////////////////////////////////*/

    function testNonceIsCorrectForAccountContract() public {
        address owner = makeAddr("owner");
        simpleAccount = new SimpleAccount(entryPoint, owner);

        // calling getNonce of SimpleAccount which inherits BaseAccount
        uint256 nonce = simpleAccount.getNonce();

        // account contract is newly deployed so nonce for it should be zero
        assertEq(nonce, 0);

        // increment and test nonce of default key
        uint192 key = 0;

        vm.prank(address(simpleAccount));
        entryPoint.incrementNonce(key);

        // calling getNonce of EntryPoint
        nonce = entryPoint.getNonce(address(simpleAccount), key);

        assertEq(nonce, 1);

        // increment and test nonce of custom key
        key = 123;

        nonce = entryPoint.getNonce(address(simpleAccount), key);
        uint256 expectedNonce = uint256(key << 64 | 0);
        assertEq(nonce, expectedNonce);

        vm.prank(address(simpleAccount));
        entryPoint.incrementNonce(key);

        // calling getNonce of EntryPoint
        nonce = entryPoint.getNonce(address(simpleAccount), key);
        expectedNonce = uint256(key << 64 | 1);
        assertEq(nonce, expectedNonce);
    }

    /*//////////////////////////////////////////////////////////////
                         _CREATESENDERIFNEEDED
    //////////////////////////////////////////////////////////////*/

    function generateUserOpInfo(address _sender, uint256 _verificationGasLimit)
        public
        pure
        returns (EntryPoint.UserOpInfo memory, bytes32)
    {
        EntryPoint.MemoryUserOp memory mUserOp = EntryPoint.MemoryUserOp({
            sender: _sender,
            nonce: 0,
            verificationGasLimit: _verificationGasLimit,
            callGasLimit: 0,
            paymasterVerificationGasLimit: 0,
            paymasterPostOpGasLimit: 0,
            preVerificationGas: 0,
            paymaster: address(0),
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0
        });

        bytes32 userOpHash = keccak256("CreateUserOpHashForUserOpInfo");
        EntryPoint.UserOpInfo memory userOpInfo =
            EntryPoint.UserOpInfo({mUserOp: mUserOp, userOpHash: userOpHash, prefund: 0, contextOffset: 0, preOpGas: 0});

        return (userOpInfo, userOpHash);
    }

    function testRevertIfSenderAlreadyConstructed() public {
        AccountFactory factory = new AccountFactory();
        address owner = makeAddr("owner");
        bytes32 salt = keccak256("createSaltForTheAccountFactory");
        uint256 verificationGas = type(uint24).max;
        uint256 userOpIndex = 0;

        bytes memory initCode = abi.encodePacked(
            address(factory),
            abi.encodeWithSelector(AccountFactory.createAccount.selector, address(entryPoint), owner, salt)
        );

        bytes32 byteCodeHash =
            keccak256(abi.encodePacked(type(SimpleAccount).creationCode, abi.encode(entryPoint, owner)));
        address expectedSender = factory.getAccountAddress(salt, byteCodeHash);

        (EntryPoint.UserOpInfo memory userOpInfo,) = generateUserOpInfo(expectedSender, verificationGas);

        entryPoint.expose_createSenderIfNeeded(userOpIndex, userOpInfo, initCode);

        vm.expectRevert(
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, userOpIndex, "AA10 sender already constructed")
        );
        entryPoint.expose_createSenderIfNeeded(userOpIndex, userOpInfo, initCode);
    }

    function testRevertIfAA13() public {
        AccountFactory factory = new AccountFactory();
        address owner = makeAddr("owner");
        bytes32 salt = keccak256("createSaltForTheAccountFactory");
        uint256 verificationGas = type(uint16).max;
        uint256 userOpIndex = 0;

        bytes memory initCode = abi.encodePacked(
            address(factory),
            abi.encodeWithSelector(AccountFactory.createAccount.selector, address(entryPoint), owner, salt)
        );

        bytes32 byteCodeHash =
            keccak256(abi.encodePacked(type(SimpleAccount).creationCode, abi.encode(entryPoint, owner)));
        address expectedSender = factory.getAccountAddress(salt, byteCodeHash);

        (EntryPoint.UserOpInfo memory userOpInfo,) = generateUserOpInfo(expectedSender, verificationGas);

        vm.expectRevert(
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, userOpIndex, "AA13 initCode failed or OOG")
        );
        entryPoint.expose_createSenderIfNeeded(userOpIndex, userOpInfo, initCode);
    }

    function testRevertIfAA14() public {
        AccountFactory factory = new AccountFactory();
        address owner = makeAddr("owner");
        bytes32 salt = keccak256("createSaltForTheAccountFactory");
        uint256 verificationGas = type(uint24).max;
        uint256 userOpIndex = 0;

        bytes memory initCode = abi.encodePacked(
            address(factory),
            abi.encodeWithSelector(AccountFactory.createAccount.selector, address(entryPoint), owner, salt)
        );

        address wrongSender = makeAddr("wrongSender");

        (EntryPoint.UserOpInfo memory userOpInfo,) = generateUserOpInfo(wrongSender, verificationGas);

        vm.expectRevert(
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, userOpIndex, "AA14 initCode must return sender")
        );
        entryPoint.expose_createSenderIfNeeded(userOpIndex, userOpInfo, initCode);
    }

    function testRevertIfAA15() public {
        EmptySenderFactory factory = new EmptySenderFactory();
        address owner = makeAddr("owner");
        bytes32 salt = keccak256("createSaltForTheAccountFactory");
        uint256 verificationGas = type(uint24).max;
        uint256 userOpIndex = 0;

        bytes memory initCode = abi.encodePacked(
            address(factory),
            abi.encodeWithSelector(AccountFactory.createAccount.selector, address(entryPoint), owner, salt)
        );

        address expectedSender = factory.getAccountAddress();

        (EntryPoint.UserOpInfo memory userOpInfo,) = generateUserOpInfo(expectedSender, verificationGas);

        vm.expectRevert(
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, userOpIndex, "AA15 initCode must create sender")
        );
        entryPoint.expose_createSenderIfNeeded(userOpIndex, userOpInfo, initCode);
    }

    function testSenderIsCreated() public {
        AccountFactory factory = new AccountFactory();
        address owner = makeAddr("owner");
        bytes32 salt = keccak256("createSaltForTheAccountFactory");
        uint256 verificationGas = type(uint24).max;
        uint256 userOpIndex = 0;

        bytes memory initCode = abi.encodePacked(
            address(factory),
            abi.encodeWithSelector(AccountFactory.createAccount.selector, address(entryPoint), owner, salt)
        );

        bytes32 byteCodeHash =
            keccak256(abi.encodePacked(type(SimpleAccount).creationCode, abi.encode(entryPoint, owner)));
        address expectedSender = factory.getAccountAddress(salt, byteCodeHash);

        (EntryPoint.UserOpInfo memory userOpInfo, bytes32 userOpHash) =
            generateUserOpInfo(expectedSender, verificationGas);

        vm.expectEmit(true, true, false, true, address(entryPoint));
        emit IEntryPoint.AccountDeployed(userOpHash, expectedSender, address(factory), address(0)); // paymaster address is zero address
        entryPoint.expose_createSenderIfNeeded(userOpIndex, userOpInfo, initCode);
    }

    /*//////////////////////////////////////////////////////////////
                            GETSENDERADDRESS
    //////////////////////////////////////////////////////////////*/

    function testReturnsCorrectSenderAddress() public {
        AccountFactory factory = new AccountFactory();

        address owner = makeAddr("owner");
        bytes32 salt = keccak256("createSaltForTheAccountFactory");

        bytes memory initCode = abi.encodePacked(
            address(factory),
            abi.encodeWithSelector(AccountFactory.createAccount.selector, address(entryPoint), owner, salt)
        );

        bytes32 byteCodeHash =
            keccak256(abi.encodePacked(type(SimpleAccount).creationCode, abi.encode(entryPoint, owner)));

        address expectedAddress = factory.getAccountAddress(salt, byteCodeHash);

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.SenderAddressResult.selector, expectedAddress));
        entryPoint.getSenderAddress(initCode);
    }

    /*//////////////////////////////////////////////////////////////
                          _VALIDATEPREPAYMENT
    //////////////////////////////////////////////////////////////*/

    /// @dev slice the bytes memory variable
    function sliceBytes(bytes memory data, uint256 start, uint256 length) internal pure returns (bytes memory) {
        require(data.length >= start + length, "Slice out of bounds");
        bytes memory result = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            result[i] = data[start + i];
        }
        return result;
    }

    /// @dev generates OpIndex, PackedUserOperation and UserOpInfo for following tests
    function generatePUOAndUOI(uint256 verificationGasLimt, uint256 nonce, bytes memory callData)
        internal
        returns (PackedUserOperation memory, EntryPoint.UserOpInfo memory, uint256)
    {
        Account memory owner = makeAccount("owner");
        uint256 depositAmount = 10 ether;

        address accountContract;
        bytes memory userOpCalldata;
        if (callData.length == 0) {
            accountContract = address(new SimpleAccount(entryPoint, owner.addr));
            userOpCalldata = hex"";
        } else {
            // extract address of accountContract from callData
            assembly {
                accountContract := mload(add(callData, 20))
            }
            userOpCalldata = sliceBytes(callData, 20, callData.length - 20);
        }

        entryPoint.depositTo{value: depositAmount}(address(accountContract));

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: accountContract,
            nonce: nonce,
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32(verificationGasLimt << 128 | uint256(100_000)),
            preVerificationGas: uint256(100_000),
            gasFees: bytes32(uint256(20) << 128 | uint256(20)),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.key, userOpHash);
        userOp.signature = abi.encodePacked(r, s, v);

        EntryPoint.MemoryUserOp memory mUserOp = EntryPoint.MemoryUserOp(address(0), 0, 0, 0, 0, 0, 0, address(0), 0, 0);
        EntryPoint.UserOpInfo memory userOpInfo = EntryPoint.UserOpInfo(mUserOp, hex"", 0, 0, 0);

        uint256 opIndex = 0;
        return (userOp, userOpInfo, opIndex);
    }

    function testValidatePrepayment() public {
        uint256 verificationGasLimit = 100_000;
        uint256 nonce = 0;

        uint256 expectedValidationData = 0;
        uint256 expectedPaymasterValidationData = 0;

        (PackedUserOperation memory userOp, EntryPoint.UserOpInfo memory userOpInfo, uint256 opIndex) =
            generatePUOAndUOI(verificationGasLimit, nonce, bytes(""));

        (uint256 validationData, uint256 paymasterValidationData) =
            entryPoint.expose_validatePrepayment(opIndex, userOp, userOpInfo);

        assertEq(validationData, expectedValidationData);
        assertEq(paymasterValidationData, expectedPaymasterValidationData);
    }

    function testValidatePrepaymentReverts() public {
        // gas overflow
        uint256 verificationGasLimit = type(uint128).max;
        uint256 nonce = 0;

        (PackedUserOperation memory userOp, EntryPoint.UserOpInfo memory userOpInfo, uint256 opIndex) =
            generatePUOAndUOI(verificationGasLimit, nonce, bytes(""));

        vm.expectRevert("AA94 gas values overflow");
        entryPoint.expose_validatePrepayment(opIndex, userOp, userOpInfo);

        // wrong nonce
        verificationGasLimit = 38_000;
        nonce = 1;

        (userOp, userOpInfo, opIndex) = generatePUOAndUOI(verificationGasLimit, nonce, bytes(""));

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, opIndex, "AA25 invalid account nonce"));
        entryPoint.expose_validatePrepayment(opIndex, userOp, userOpInfo);

        // not enough gas
        nonce = 0;
        (userOp, userOpInfo, opIndex) = generatePUOAndUOI(verificationGasLimit, nonce, bytes(""));

        vm.expectRevert(
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, opIndex, "AA26 over verificationGasLimit")
        );
        entryPoint.expose_validatePrepayment(opIndex, userOp, userOpInfo);
    }

    /*//////////////////////////////////////////////////////////////
                          SUPPORTED INTERFACES
    //////////////////////////////////////////////////////////////*/

    function testEntryPointSupportsCorrectInterfaces() public view {
        bytes4 expectedInterfaceId = type(IEntryPoint).interfaceId;

        // check supports IEntryPoint
        bool result = entryPoint.supportsInterface(expectedInterfaceId);
        assertEq(result, true);

        // check supports IStakeManager
        expectedInterfaceId = type(IStakeManager).interfaceId;

        result = entryPoint.supportsInterface(expectedInterfaceId);
        assertEq(result, true);

        // check supports INonceManager
        expectedInterfaceId = type(INonceManager).interfaceId;

        result = entryPoint.supportsInterface(expectedInterfaceId);
        assertEq(result, true);

        // check supports combined interfaceId

        expectedInterfaceId =
            (type(IEntryPoint).interfaceId ^ type(IStakeManager).interfaceId ^ type(INonceManager).interfaceId);

        result = entryPoint.supportsInterface(expectedInterfaceId);
        assertEq(result, true);

        // check returns false on wrong interface id
        expectedInterfaceId = hex"a3b2c1d0";

        result = entryPoint.supportsInterface(expectedInterfaceId);
        assertEq(result, false);
    }

    /*//////////////////////////////////////////////////////////////
                             _EXECUTEUSEROP
    //////////////////////////////////////////////////////////////*/

    function testExecuteUserOpRevertsOnLowPrefuns() public {
        SimpleAccountRevert accountContract = new SimpleAccountRevert(entryPoint, SimpleAccountRevert.Mode.SendLessPreFund);
        
        uint256 verificationGasLimit = 0;
        uint256 nonce = 0;

        bytes memory callData = abi.encodePacked(address(accountContract), SimpleAccountRevert.failExecute.selector);

        (PackedUserOperation memory userOp, EntryPoint.UserOpInfo memory userOpInfo, uint256 opIndex) =
            generatePUOAndUOI(verificationGasLimit, nonce, callData);
    }
}
