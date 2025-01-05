// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.24;

import {SimpleAccount} from "src/samples/SimpleAccount.sol";
import {IAccountExecute} from "src/interfaces/IAccountExecute.sol";
import {IEntryPoint} from "src/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";

contract SimpleAccountExecuteUserOp is SimpleAccount, IAccountExecute {
    error SimpleAccountExecuteUserOp__callFailed();

    constructor(IEntryPoint entryPoint, address owner) SimpleAccount(entryPoint, owner) {}

    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) public {
        (userOpHash);
        _requireFromEntryPoint();

        bytes memory parsedCalldata = userOp.callData[4:];

        (address dest, uint256 value, bytes memory callData) = abi.decode(parsedCalldata, (address, uint256, bytes));

        (bool success,) = dest.call{value: value}(callData);
        if (!success) {
            revert SimpleAccountExecuteUserOp__callFailed();
        }
    }
}
