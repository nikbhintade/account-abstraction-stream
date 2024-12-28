// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {console2 as console} from "forge-std/console2.sol";
import {BasePaymaster} from "src/core/BasePaymaster.sol";
import {IEntryPoint} from "src/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "src/core/Helpers.sol";

contract Paymaster is BasePaymaster {
    mapping(address accountContract => bool status) private whitelist;

    constructor(IEntryPoint entryPoint) BasePaymaster(entryPoint) {}

    function _validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        internal
        view
        override
        returns (bytes memory context, uint256 validationData)
    {
        (userOpHash, maxCost);
        console.log(userOp.sender);
        console.log(whitelist[userOp.sender]);
        if (whitelist[userOp.sender]) {
            console.log("1");
            return (hex"", SIG_VALIDATION_SUCCESS);
        } else {
            console.log("2");
            return (hex"", SIG_VALIDATION_FAILED);
        }
    }

    function addAddressToWhitelist(address accountContract) external onlyOwner {
        whitelist[accountContract] = true;
    }

    function removeAddressFromWhitelist(address accountContract) external onlyOwner {
        whitelist[accountContract] = false;
    }

    function checkIfWhitelisted(address accountContract) public view returns (bool) {
        return whitelist[accountContract];
    }
}
