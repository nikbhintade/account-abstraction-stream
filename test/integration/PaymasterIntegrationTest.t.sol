// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console2 as console} from "forge-std/Test.sol";
import {EntryPoint} from "src/core/EntryPoint.sol";
import {SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "src/core/Helpers.sol";
import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "src/interfaces/IEntryPoint.sol";
import {SimpleAccount} from "src/samples/SimpleAccount.sol";
import {Paymaster} from "src/samples/Paymaster.sol";

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {Vm} from "forge-std/Vm.sol";

contract PaymasterIntegrationTest is Test {
    Paymaster private paymaster;
    EntryPoint private entryPoint;
    SimpleAccount private simpleAccount;
    uint256 initalBalance;

    Account private owner;

    function setUp() external {
        owner = makeAccount("owner");
        entryPoint = new EntryPoint();
        paymaster = new Paymaster(entryPoint);
        simpleAccount = new SimpleAccount(entryPoint, owner.addr);

        initalBalance = 10 ether;
    }

    uint256 amountToSend = 1 ether;

    function testUserOpExecutionWithPaymasterIsSuccessful() external {
        // create receiver & bundler
        address receiver = makeAddr("receiver");
        address bundler = makeAddr("bundler");

        // deal some ether to bundler, simpleaccount
        // uint256 initalBalance = 10 ether;

        vm.deal(address(simpleAccount), initalBalance);
        vm.deal(bundler, initalBalance);

        entryPoint.depositTo{value: initalBalance}(address(paymaster));

        // add simpleaccount to whitelist
        paymaster.addAddressToWhitelist(address(simpleAccount));

        // create user operation
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(simpleAccount),
            nonce: 0,
            initCode: hex"",
            callData: abi.encodeWithSelector(SimpleAccount.execute.selector, receiver, amountToSend, hex""),
            accountGasLimits: bytes32(uint256(100_000) << 128 | uint256(100_000)),
            preVerificationGas: uint256(100_000),
            gasFees: bytes32(uint256(20) << 128 | uint256(20)),
            paymasterAndData: abi.encodePacked(address(paymaster), uint128(100_000), uint128(0)),
            signature: hex""
        });

        // get user operation hash and formatted
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        // bytes32 fUserOp = MessageHashUtils.toEthSignedMessageHash(userOpHash);

        // sign the formatted hash
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.key, userOpHash);

        // pack the signature components and add the signature to userop
        userOp.signature = abi.encodePacked(r, s, v);

        // create PackedUserOperation[]
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // check for UserOperationEvent
        // call entry point with bundler
        vm.prank(bundler);
        vm.recordLogs();
        vm.expectEmit(true, true, true, false, address(entryPoint));
        emit IEntryPoint.UserOperationEvent(userOpHash, address(simpleAccount), address(paymaster), 0, false, 0, 0);
        entryPoint.handleOps(userOps, payable(bundler));

        // decode the recorded events and check if parameters are correct
        Vm.Log[] memory logs = vm.getRecordedLogs();
        (uint256 nonce, bool success, uint256 actualGasCost) = abi.decode(logs[2].data, (uint256, bool, uint256));

        vm.assertEq(nonce, 0);
        vm.assertEq(success, true);

        // check receiver balance
        vm.assertEq(receiver.balance, amountToSend);

        // check simple account balance is round number
        vm.assertEq(address(simpleAccount).balance, initalBalance - amountToSend);

        // check paymaster deposit
        vm.assertEq(entryPoint.balanceOf(address(paymaster)), initalBalance - actualGasCost);

        // check if bundler received correct amount
        vm.assertEq(bundler.balance, initalBalance + actualGasCost);
    }
}
