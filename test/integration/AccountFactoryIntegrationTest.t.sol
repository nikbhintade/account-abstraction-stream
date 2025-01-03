// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {EntryPoint} from "src/core/EntryPoint.sol";
import {AccountFactory} from "src/samples/AccountFactory.sol";
import {SimpleAccount} from "src/samples/SimpleAccount.sol";
import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "src/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {console} from "forge-std/console.sol";

contract SimpleAccountFactoryIntegration is Test {
    AccountFactory private simpleAccountFactory;

    EntryPoint private entryPoint;
    Account private owner;
    Account private bundler;

    function setUp() external {
        owner = makeAccount("owner");
        bundler = makeAccount("bundler");
        // vm.deal(bundler.addr, 10 ether);

        simpleAccountFactory = new AccountFactory();

        entryPoint = new EntryPoint();
    }

    function testFactoryWithEntryPoint() public {
        console.log("test account address", address(this));
        console.log("entryPoint address", address(entryPoint));
        bytes32 salt = keccak256("CreateASaltForFactory");

        address factory = address(simpleAccountFactory);
        bytes memory factoryData =
            abi.encodeWithSelector(AccountFactory.createAccount.selector, address(entryPoint), owner.addr, salt);

        bytes32 byteCodeHash =
            keccak256(abi.encodePacked(type(SimpleAccount).creationCode, abi.encode(IEntryPoint(entryPoint), owner.addr)));

        address sender = simpleAccountFactory.getAccountAddress(salt, byteCodeHash);

        entryPoint.depositTo{value: 10 ether}(sender);
        bytes memory initCode = abi.encodePacked(factory, factoryData);

        bytes32 accountGasLimits = bytes32(uint256(type(uint24).max) << 128 | uint256(type(uint24).max));

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: sender,
            nonce: 0,
            initCode: initCode,
            callData: hex"",
            accountGasLimits: accountGasLimits,
            preVerificationGas: type(uint24).max,
            gasFees: bytes32(uint256(20) << 128 | uint256(20)),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.key, userOpHash);

        userOp.signature = abi.encodePacked(r, s, v);

        // 8. Generate the user operations array to pass to the handleOps function

        PackedUserOperation[] memory userOperationArray = new PackedUserOperation[](1);
        userOperationArray[0] = userOp;

        entryPoint.handleOps(userOperationArray, payable(bundler.addr));
    }
}
