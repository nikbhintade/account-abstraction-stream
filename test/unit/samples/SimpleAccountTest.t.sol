// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console2 as console} from "forge-std/Test.sol";

import {SimpleAccount} from "src/samples/SimpleAccount.sol";
import {IEntryPoint} from "src/interfaces/IEntryPoint.sol";
import {EntryPoint} from "src/core/EntryPoint.sol";

import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "src/core/Helpers.sol";

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract RevertOnCalledByExecute {
    fallback() external {
        revert("revert on receiving ether");
    }
}

contract SimpleAccountHarness is SimpleAccount {
    constructor(IEntryPoint _entryPoint, address _owner) SimpleAccount(_entryPoint, _owner) {}

    function expose_validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        returns (uint256 validationData)
    {
        return _validateSignature(userOp, userOpHash);
    }
}

/// @title Unit Tests for the SimpleAccount (src/samples/SimpleAccount.sol) contract

contract SimepleAccountTest is Test {
    // instance of SimpleAccount and EntryPoint
    SimpleAccount private simpleAccount;
    address private entryPoint;

    function setUp() external {
        entryPoint = makeAddr("entryPoint");

        simpleAccount = new SimpleAccount(IEntryPoint(entryPoint), msg.sender);
    }

    function test_check_if_entrypoint_address_is_correct() external view {
        address entryPointAddress = address(simpleAccount.entryPoint());

        assertEq(entryPoint, entryPointAddress);
    }

    function test_if_execute_works_properly() external {
        address randomAddress = makeAddr("randomAddress");

        vm.deal(address(simpleAccount), 10 ether);
        vm.prank(entryPoint);
        simpleAccount.execute(randomAddress, 1 ether, hex"");

        assertEq(address(simpleAccount).balance, 9 ether);
        assertEq(randomAddress.balance, 1 ether);
    }

    function test_if_not_called_from_entrypoint_execute_reverts() external {
        address randomAddress = makeAddr("randomAddress");

        vm.deal(address(simpleAccount), 10 ether);
        vm.expectRevert(bytes("account: not from EntryPoint"));
        simpleAccount.execute(randomAddress, 1 ether, hex"");
    }

    function test_execute_reverts_with_correct_revert_message_and_error() external {
        RevertOnCalledByExecute revertOnCalledByExecute = new RevertOnCalledByExecute();

        vm.deal(address(simpleAccount), 10 ether);
        vm.prank(entryPoint);
        vm.expectRevert(abi.encodeWithSelector(SimpleAccount.SimpleAccount__callFailed.selector, hex"")); // why test is not successful when custom error selector is inculded
        simpleAccount.execute(address(revertOnCalledByExecute), 1 ether, hex"");
    }

    function test_validate_signature_returns_correct_value_for_correct_signature() external {
        EntryPoint entryPointInstance = new EntryPoint();
        (address owner, uint256 ownerPK) = makeAddrAndKey("owner");

        SimpleAccountHarness simpleAccountHarness = new SimpleAccountHarness(entryPointInstance, owner);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(simpleAccountHarness),
            nonce: 1,
            initCode: hex"",
            callData: hex"",
            accountGasLimits: hex"",
            preVerificationGas: type(uint64).max,
            gasFees: hex"",
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPointInstance.getUserOpHash(userOp); // this is userOpHash
        // bytes32 formattedDigest = MessageHashUtils.toEthSignedMessageHash(userOp);

        // signature components
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, userOpHash);

        // pack above components in correct order
        userOp.signature = abi.encodePacked(r, s, v);

        uint256 result = simpleAccountHarness.expose_validateSignature(userOp, userOpHash);

        assertEq(result, SIG_VALIDATION_SUCCESS);
    }

    function test_validate_signature_returns_correct_value_for_incorrect_signature() external {
        EntryPoint entryPointInstance = new EntryPoint();
        (address owner,) = makeAddrAndKey("owner");
        (, uint256 randomPK) = makeAddrAndKey("randomUser");

        SimpleAccountHarness simpleAccountHarness = new SimpleAccountHarness(entryPointInstance, owner);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(simpleAccountHarness),
            nonce: 1,
            initCode: hex"",
            callData: hex"",
            accountGasLimits: hex"",
            preVerificationGas: type(uint64).max,
            gasFees: hex"",
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 digest = entryPointInstance.getUserOpHash(userOp); // this is userOpHash
        bytes32 formattedDigest = MessageHashUtils.toEthSignedMessageHash(digest);

        // signature components
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(randomPK, formattedDigest);

        // pack above components in correct order
        userOp.signature = abi.encodePacked(r, s, v);

        uint256 result = simpleAccountHarness.expose_validateSignature(userOp, digest);

        assertEq(result, SIG_VALIDATION_FAILED);
    }
}
