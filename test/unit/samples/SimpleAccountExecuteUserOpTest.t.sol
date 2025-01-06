// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {SimpleAccountExecuteUserOp} from "src/samples/SimpleAccountExecuteUserOp.sol";
import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";
import {EntryPoint} from "src/core/EntryPoint.sol";

contract SimpleAccountExecuteUserOpTest is Test {
    SimpleAccountExecuteUserOp private simpleAccount;
    EntryPoint private entryPoint;
    Account private owner;

    function setUp() public {
        entryPoint = new EntryPoint();
        owner = makeAccount("owner");
        simpleAccount = new SimpleAccountExecuteUserOp(entryPoint, owner.addr);
    }

    function testSimpleAccountExecuteWorks() public {
        // create receiver
        address receiver = makeAddr("receiver");

        // deal 10 eth to simpleAccount
        vm.deal(address(simpleAccount), 10 ether);

        // create callData

        bytes memory callData = abi.encodeWithSelector(SimpleAccountExecuteUserOp.executeUserOp.selector, receiver, 1 ether, hex"");

        // create userOp & userOpHash
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(simpleAccount),
            nonce: 0,
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32(uint256(100_000) << 128 | uint256(100_000)),
            preVerificationGas: uint256(100_0000),
            gasFees: bytes32(uint256(50) << 128 | uint256(50)),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        // call executeUserOp
        vm.prank(address(entryPoint));
        simpleAccount.executeUserOp(userOp, userOpHash);

        // check if balances are correct
        assertEq(receiver.balance, 1 ether);
        assertEq(address(simpleAccount).balance, 9 ether);
    }
}
