// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console2 as console} from "forge-std/Test.sol";

import {IEntryPoint} from "src/interfaces/IEntryPoint.sol";
import {BaseAccount} from "src/core/BaseAccount.sol";
import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "src/core/Helpers.sol";

contract SimpleAccountRevert is BaseAccount {
    IEntryPoint private s_entryPoint;
    Mode private s_mode;

    enum Mode {
        RevertOnValidate,
        SendLessPreFund
    }

    constructor(IEntryPoint _entryPoint, Mode mode) {
        s_entryPoint = _entryPoint;
        s_mode = mode;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return s_entryPoint;
    }

    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        override
        returns (uint256 validationData)
    {
        (userOp, userOpHash);
        if (s_mode == Mode.RevertOnValidate) {
            revert("Validate Reverted");
        } else {
            return SIG_VALIDATION_SUCCESS;
        }
    }

    function failExecute() public pure {
        revert();
    }

    function executeSuccessful() public pure {}

    function _payPrefund(uint256 missingAccountFunds) internal override {
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{
                value: (s_mode == Mode.SendLessPreFund) ? missingAccountFunds / 2 : missingAccountFunds,
                gas: type(uint256).max
            }("");
            (success);
            //ignore failure (its EntryPoint's job to verify, not account.)
        }
    }
}
