// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console2 as console} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";

import {EntryPoint} from "src/core/EntryPoint.sol";
import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "src/interfaces/IEntryPoint.sol";
import {SimpleAccount} from "src/samples/SimpleAccount.sol";

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract SimpleAccountIntegration is Test {
    Account private owner;
    Account private receiver;
    Account private bundler;

    EntryPoint private entryPoint;
    SimpleAccount private simpleAccount;

    function setUp() external {
        owner = makeAccount("owner");
        receiver = makeAccount("receiver");
        bundler = makeAccount("bundler");

        entryPoint = new EntryPoint();
        simpleAccount = new SimpleAccount(entryPoint, owner.addr);

        vm.deal(bundler.addr, 10 ether);
        vm.deal(address(simpleAccount), 10 ether);
        // entryPoint.depositTo{value: 1 ether}(address(simpleAccount));
    }

    function testUserOperationIsScuessfullyExecutedViaEntryPoint() external {
        bytes memory _calldata = abi.encodeWithSelector(SimpleAccount.execute.selector, receiver.addr, 1 ether, "");

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(simpleAccount),
            nonce: 0,
            initCode: hex"",
            callData: _calldata,
            accountGasLimits: bytes32(uint256(100_000) << 128 | uint256(100_000)),
            preVerificationGas: uint256(100_0000),
            gasFees: bytes32(uint256(50) << 128 | uint256(50)),
            paymasterAndData: hex"",
            signature: hex""
        });

        // userOpHash
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        // sign it and add signature to userOP
        // bytes32 formattedUserOpHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.key, userOpHash);

        userOp.signature = abi.encodePacked(r, s, v);

        // create array of userOp's
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);

        userOps[0] = userOp;

        // check if correct events are emitted
        // send it to entryPoint
        vm.prank(bundler.addr);
        vm.expectEmit(true, true, true, false, address(entryPoint));
        emit IEntryPoint.UserOperationEvent(userOpHash, address(simpleAccount), address(0), 0, false, 0, 0);
        vm.recordLogs();
        entryPoint.handleOps(userOps, payable(bundler.addr));

        // check our assumptions
        vm.assertEq(receiver.addr.balance, 1 ether);

        Vm.Log[] memory logs = vm.getRecordedLogs();

        vm.assertEq(logs.length, 3);
        (uint256 nonce, bool success) = abi.decode(logs[2].data, (uint256, bool));
        vm.assertEq(nonce, 0);
        vm.assertEq(success, true);
    }
}
