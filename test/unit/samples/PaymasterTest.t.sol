// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {EntryPoint} from "src/core/EntryPoint.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "src/core/Helpers.sol";
import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";
import {Paymaster} from "src/samples/Paymaster.sol";

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

    function setUp() external {
        EntryPoint entryPoint = new EntryPoint();
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
}
