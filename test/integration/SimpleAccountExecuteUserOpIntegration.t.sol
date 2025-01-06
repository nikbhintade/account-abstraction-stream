// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {SimpleAccountExecuteUserOp} from "src/samples/SimpleAccountExecuteUserOp.sol";
import {EntryPoint} from "src/core/EntryPoint.sol";
import {IEntryPoint} from "src/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";

contract SimpleAccountExecuteUserOpIntegration is Test {
    EntryPoint private entryPoint;
    Account private owner;
    SimpleAccountExecuteUserOp private simpleAccount;

    function setUp() public {
        entryPoint = new EntryPoint();
        owner = makeAccount("owner");

        simpleAccount = new SimpleAccountExecuteUserOp(entryPoint, owner.addr);
    }

    function testExecuteUserOpWorksWithEntryPoint() public {
        // create receiver & bundler
        address receiver = makeAddr("receiver");
        address bundler = makeAddr("bundler");

        // deal 10 ether to simpleAccount and bundler
        uint256 amountToDeal = 10 ether;

        vm.deal(address(simpleAccount), amountToDeal);
        vm.deal(bundler, amountToDeal);
        
        // costruct calldata
        bytes memory callData = abi.encodeWithSelector(SimpleAccountExecuteUserOp.executeUserOp.selector, receiver, 1 ether, hex"");

        // create PackedUserOperation
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(simpleAccount),
            nonce: 0,
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32(uint256(100_000) << 128 | uint256(100_000)),
            preVerificationGas: uint256(100_000),
            gasFees: bytes32(uint256(0) << 128 | uint256(0)),
            paymasterAndData: hex"",
            signature: hex""
        });

        // get userOpHash
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        // sign the hash
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.key, userOpHash);

        // add the signature to userOp
        userOp.signature = abi.encodePacked(r, s, v);

        // create userOp[] & add userOp to it
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // call entryPoint & do the vm.expectEmit
        vm.prank(bundler); // not needed but I wanted to do it so why not??
        vm.expectEmit(true, true, true, false, address(entryPoint));
        emit IEntryPoint.UserOperationEvent(userOpHash, address(simpleAccount), address(0), 0, false, 0, 0);
        entryPoint.handleOps(userOps, payable(bundler));

        // check balances of simpleAccount and receiver
        assertEq(address(simpleAccount).balance, 9 ether);
        assertEq(receiver.balance, 1 ether);
    }
}