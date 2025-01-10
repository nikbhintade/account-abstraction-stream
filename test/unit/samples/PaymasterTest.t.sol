// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {EntryPoint} from "src/core/EntryPoint.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "src/core/Helpers.sol";
import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";
import {Paymaster} from "src/samples/Paymaster.sol";
import {IStakeManager} from "src/interfaces/IStakeManager.sol";
import {IPaymaster} from "src/interfaces/IPaymaster.sol";

contract PaymasterHarness is Paymaster {
    constructor(EntryPoint entryPoint) Paymaster(entryPoint) {}

    function expose_validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        external
        view
        returns (bytes memory context, uint256 validationData)
    {
        return _validatePaymasterUserOp(userOp, userOpHash, maxCost);
    }
}

contract PaymasterTest is Test {
    PaymasterHarness private paymaster;
    EntryPoint private entryPoint;

    function setUp() external {
        entryPoint = new EntryPoint();
        paymaster = new PaymasterHarness(entryPoint); // owner of the paymaster is the test contract
    }

    function testAddAndRemoveFromWhitelistWorks() external {
        address testUser = makeAddr("testUser");
        // check default value is false - don't need this but still decided to add it
        vm.assertEq(false, paymaster.checkIfWhitelisted(testUser));

        // add to whitelist
        paymaster.addAddressToWhitelist(testUser);
        vm.assertEq(true, paymaster.checkIfWhitelisted(testUser));

        // remove from whitelist
        paymaster.removeAddressFromWhitelist(testUser);
        vm.assertEq(false, paymaster.checkIfWhitelisted(testUser));
    }

    function testAccessControlOfAddAndRemoveFunction() external {
        // should revert on accessed from non-owner/unauthorized address
        address randomUser = makeAddr("randomUser");

        vm.prank(randomUser);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(randomUser)));
        paymaster.addAddressToWhitelist(randomUser);

        vm.prank(randomUser);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(randomUser)));
        paymaster.removeAddressFromWhitelist(randomUser);
    }

    /*//////////////////////////////////////////////////////////////
                      TESTING PAYMASTER VALIDATION
    //////////////////////////////////////////////////////////////*/

    function testPaymasterValidationIsSuccessful() external {
        address sender = makeAddr("sender");

        paymaster.addAddressToWhitelist(sender);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: sender,
            nonce: 0,
            initCode: hex"",
            callData: hex"",
            accountGasLimits: hex"",
            preVerificationGas: 0,
            gasFees: hex"",
            paymasterAndData: hex"",
            signature: hex""
        });

        (bytes memory context, uint256 validationData) = paymaster.expose_validatePaymasterUserOp(userOp, hex"", 0);

        vm.assertEq(validationData, SIG_VALIDATION_SUCCESS);
        vm.assertEq(context, hex"");
    }

    function testPaymasterValidationFails() external {
        address sender = makeAddr("sender");

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: sender,
            nonce: 0,
            initCode: hex"",
            callData: hex"",
            accountGasLimits: hex"",
            preVerificationGas: 0,
            gasFees: hex"",
            paymasterAndData: hex"",
            signature: hex""
        });

        (bytes memory context, uint256 validationData) = paymaster.expose_validatePaymasterUserOp(userOp, hex"", 0);

        vm.assertEq(validationData, SIG_VALIDATION_FAILED);
        vm.assertEq(context, hex"");
    }

    // test cases:
    // 1. deposit directly from paymaster
    // 2. stake, unlock, & withdraw from paymaster

    function testDepositAndWithdrawFromPaymasterContract() public {
        uint256 deposit = 1 ether;

        paymaster.deposit{value: deposit}();

        uint256 actualDeposit = paymaster.getDeposit();

        assertEq(deposit, actualDeposit);

        address payable receiver = payable(makeAddr("receiver"));

        paymaster.withdrawTo(receiver, deposit);

        actualDeposit = paymaster.getDeposit();

        uint256 expectedDepositAfterWithdrawal = 0;

        assertEq(expectedDepositAfterWithdrawal, actualDeposit);
    }

    function testStakeFunctionsFromPaymaster() public {
        uint256 stake = 1 ether;
        uint32 unstakeDelaySec = 100;

        address payable receiver = payable(makeAddr("receiver"));

        // 1. add deposit
        paymaster.addStake{value: stake}(unstakeDelaySec);

        // check amount of stake
        IStakeManager.DepositInfo memory depositInfo = entryPoint.getDepositInfo(address(paymaster));
        assertEq(depositInfo.stake, stake);

        // 2. unlock deposit
        paymaster.unlockStake();

        // check if stake flag is false
        depositInfo = entryPoint.getDepositInfo(address(paymaster));
        bool expectStakedValue = false;

        assertEq(depositInfo.staked, expectStakedValue);

        // 3. withdraw deposit
        uint256 newTimestamp = 101;
        vm.warp(newTimestamp);
        vm.roll(2);
        paymaster.withdrawStake(receiver);

        // check if receiver received the withdrawn stake amount
        assertEq(receiver.balance, stake);

        depositInfo = entryPoint.getDepositInfo(address(paymaster));
        uint112 expectedStakedAmount = 0;

        // check if the entity stake is zero
        assertEq(depositInfo.stake, expectedStakedAmount);
    }

    function testPaymasterRevertsOnCalledFromNotTheEntryPoint() public {

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(1),
            nonce: 0,
            initCode: hex"",
            callData: hex"",
            accountGasLimits: hex"",
            preVerificationGas: 0,
            gasFees: hex"",
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        uint256 maxCost = 0;

        vm.expectRevert("Sender not EntryPoint");
        paymaster.validatePaymasterUserOp(userOp, userOpHash, maxCost);
    }

    function testPaymasterPostOp() public {
        // reverts on not being called from entryPoint
        IPaymaster.PostOpMode mode = IPaymaster.PostOpMode.opSucceeded;
        bytes memory context = hex"";
        uint256 actualGasCost = 0;
        uint256 actualUserOpFeePerGas = 0;

        vm.expectRevert("Sender not EntryPoint");
        paymaster.postOp(mode, context, actualGasCost, actualUserOpFeePerGas);
        // reverts on called -> because we haven't overridden the post op function

        vm.prank(address(entryPoint));
        vm.expectRevert("must override");
        paymaster.postOp(mode, context, actualGasCost, actualUserOpFeePerGas);
    }
}
