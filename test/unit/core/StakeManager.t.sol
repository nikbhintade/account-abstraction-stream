// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {EntryPoint} from "src/core/EntryPoint.sol";
import {IStakeManager} from "src/interfaces/IStakeManager.sol";
import {RevertsOnEtherReceived} from "./EntryPointTest.t.sol";

contract StakeManagerTest is Test {
    EntryPoint private entryPoint;

    function setUp() public {
        entryPoint = new EntryPoint();
    }

    /*//////////////////////////////////////////////////////////////
                         TEST STAKEMANAGER.SOL
    //////////////////////////////////////////////////////////////*/

    function testRevertOnUnstakeDelaySetToZero() public {
        vm.expectRevert("must specify unstake delay");
        entryPoint.addStake(0);
    }

    function testRevertOnStakeSetToZero() public {
        vm.expectRevert("no stake specified");
        entryPoint.addStake(100);
    }

    // TO BE TESTED TOMORROW
    function testRevertOnStakeOverflow() public {
        address random = makeAddr("random");
        vm.deal(random, type(uint256).max);

        vm.prank(random);
        entryPoint.addStake{value: type(uint112).max}(100);

        vm.prank(random);
        vm.expectRevert("stake overflow");
        entryPoint.addStake{value: 1 ether}(100);
    }

    function testRevertsOnDecreasedUnstakeDelay() public {
        entryPoint.addStake{value: 1 ether}(100);

        vm.expectRevert("cannot decrease unstake time");
        entryPoint.addStake{value: 1 ether}(50);
    }

    function testAddStakeEmitsEventAndSetsDepositInfo() public {
        uint256 stake = 1 ether;
        uint32 unstakeDelaySec = 100;

        vm.expectEmit(true, false, false, true, address(entryPoint));
        emit IStakeManager.StakeLocked(address(this), stake, unstakeDelaySec);
        entryPoint.addStake{value: stake}(unstakeDelaySec);

        IStakeManager.DepositInfo memory depositInfo = entryPoint.getDepositInfo(address(this));

        IStakeManager.DepositInfo memory expectedDepositInfo = IStakeManager.DepositInfo({
            deposit: 0,
            staked: true,
            stake: uint112(stake),
            unstakeDelaySec: unstakeDelaySec,
            withdrawTime: 0
        });

        assertEq(keccak256(abi.encode(depositInfo)), keccak256(abi.encode(expectedDepositInfo)));
    }

    function testUnlockStakeRevertsOnNoStake() public {
        vm.expectRevert("not staked");
        entryPoint.unlockStake();
    }

    function testUnlockStakeRevertOnStakedEqZero() public {
        entryPoint.addStake{value: 1 ether}(100);

        entryPoint.unlockStake();

        vm.expectRevert("already unstaking");
        entryPoint.unlockStake();
    }

    function testUnlockStakeSetsDepositInfoAndEmitsEvent() public {
        uint256 stake = 1 ether;
        uint32 unstakeDelaySec = 100;

        entryPoint.addStake{value: stake}(unstakeDelaySec);

        uint48 withdrawTime = uint48(block.timestamp) + unstakeDelaySec;

        vm.expectEmit(true, false, false, true, address(entryPoint));
        emit IStakeManager.StakeUnlocked(address(this), withdrawTime);
        entryPoint.unlockStake();

        IStakeManager.DepositInfo memory depositInfo = entryPoint.getDepositInfo(address(this));

        IStakeManager.DepositInfo memory expectedDepositInfo = IStakeManager.DepositInfo({
            deposit: 0,
            staked: false,
            stake: uint112(stake),
            unstakeDelaySec: unstakeDelaySec,
            withdrawTime: withdrawTime
        });

        assertEq(keccak256(abi.encode(depositInfo)), keccak256(abi.encode(expectedDepositInfo)));
    }

    function testWithdrawStakeRevertOnNoStake() public {
        address payable receiver = payable(makeAddr("receiver"));
        vm.expectRevert("No stake to withdraw");
        entryPoint.withdrawStake(receiver);
    }

    function testWithdrawStakeRevertsOnCalledBeforeUnlock() public {
        address payable receiver = payable(makeAddr("receiver"));
        uint256 stake = 1 ether;
        uint32 unstakeDelaySec = 100;

        entryPoint.addStake{value: stake}(unstakeDelaySec);

        vm.expectRevert("must call unlockStake() first");
        entryPoint.withdrawStake(receiver);
    }

    function testWithdrawStakeRevertsOnCalledBeforeWithdrawTime() public {
        address payable receiver = payable(makeAddr("receiver"));
        uint256 stake = 1 ether;
        uint32 unstakeDelaySec = 100;

        entryPoint.addStake{value: stake}(unstakeDelaySec);
        entryPoint.unlockStake();

        vm.expectRevert("Stake withdrawal is not due");
        entryPoint.withdrawStake(receiver);
    }

    function testWithdrawStakeWorks() public {
        // 0. create receiver
        address payable receiver = payable(makeAddr("receiver"));
        uint256 stake = 1 ether;
        uint32 unstakeDelaySec = 100;
        uint256 newTimestamp = 101;

        // 1. add stake
        entryPoint.addStake{value: stake}(unstakeDelaySec);

        // 2. unlock stake
        entryPoint.unlockStake();

        // 3. warp the timestap
        vm.warp(newTimestamp);

        // 4. withdraw stake
        vm.expectEmit(true, false, false, true, address(entryPoint));
        emit IStakeManager.StakeWithdrawn(address(this), receiver, stake);
        entryPoint.withdrawStake(receiver);

        // 5. do the assertions
        IStakeManager.DepositInfo memory depositInfo = entryPoint.getDepositInfo(address(this));

        uint256 expectedStakeAfterWithdrawal = 0;

        assertEq(depositInfo.stake, expectedStakeAfterWithdrawal);
        assertEq(receiver.balance, stake);
    }
    // RevertsOnEtherReceived

    function testWithdrawStakeRevertsOnFailedEthTransfer() public {
        // 1. set variables for receiver, stake, unstakeDelaySec, newTimestamp
        address payable receiver = payable(address(new RevertsOnEtherReceived()));
        uint256 stake = 1 ether;
        uint32 unstakeDelaySec = 100;
        uint256 newTimestamp = 101;

        // 2. add & unlock stake, also change timestamp
        entryPoint.addStake{value: stake}(unstakeDelaySec);
        entryPoint.unlockStake();

        vm.warp(newTimestamp);
        vm.roll(2);

        // 3. do the assertion & withdraw stake
        vm.expectRevert("failed to withdraw stake");
        entryPoint.withdrawStake(receiver);
    }

    function testWithdrawToRevertsOnWithdrawAmtTooLarge() public {
        // 1. create payable receiver
        address payable receiver = payable(makeAddr("receiver"));
        uint256 withdrawAmount = 1 ether;

        // 2. withdraw deposit
        vm.expectRevert("Withdraw amount too large");
        entryPoint.withdrawTo(receiver, withdrawAmount);
    }

    function testWithdrawToWorks() public {
        // 1. create payable receiver & withdrawAmount variable
        address payable receiver = payable(makeAddr("receiver"));
        uint256 withdrawAmount = 1 ether;
        uint256 expectedDepositAmountAfterWithdrawal = 0 ether;

        // 2. make deposit
        entryPoint.depositTo{value: withdrawAmount}(address(this));

        // 3. withdraw deposit & check emitted events
        vm.expectEmit(true, false, false, true, address(entryPoint));
        emit IStakeManager.Withdrawn(address(this), receiver, withdrawAmount);
        entryPoint.withdrawTo(receiver, withdrawAmount);

        // 4. do the assertions (balance checks)
        assertEq(entryPoint.balanceOf(address(this)), expectedDepositAmountAfterWithdrawal);
        assertEq(receiver.balance, withdrawAmount);
    }

    function testWithdrawToRevertsOnFailedEthTransfer() public {
        // 1. create receiver that fails on eth transfer & withdraw amount
        address payable receiver = payable(address(new RevertsOnEtherReceived()));
        uint256 withdrawAmount = 1 ether;

        // 2. add deposit
        entryPoint.depositTo{value: withdrawAmount}(address(this));

        // 3. do the assertions & withdraw deposit
        vm.expectRevert("failed to withdraw");
        entryPoint.withdrawTo(receiver, withdrawAmount);
    }

    function testDirectDepositWorks() public {
        uint256 deposit = 1 ether;

        (bool success,) = address(entryPoint).call{value: deposit}("");
        require(success, "deposit failed");

        assertEq(entryPoint.balanceOf(address(this)), deposit);
    }
}
