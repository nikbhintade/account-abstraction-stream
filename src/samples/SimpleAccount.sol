// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

//// read more about erc-4337 at https://eips.ethereum.org/EIPS/eip-4337

import {BaseAccount} from "../core/BaseAccount.sol";
import {IEntryPoint} from "../interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "../core/Helpers.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SimpleAccount is BaseAccount, Ownable {
    error SimpleAccount__callFailed(bytes);

    IEntryPoint private s_entryPoint;

    constructor(IEntryPoint _entryPoint, address _owner) Ownable(_owner) {
        s_entryPoint = _entryPoint;
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
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        address signer = ECDSA.recover(digest, userOp.signature);

        if (signer == owner()) {
            return SIG_VALIDATION_SUCCESS;
        } else {
            return SIG_VALIDATION_FAILED;
        }
    }

    function execute(address destination, uint256 _value, bytes calldata data) external {
        _requireFromEntryPoint();
        (bool success, bytes memory returnData) = destination.call{value: _value}(data);
        if (!success) {
            revert SimpleAccount__callFailed(returnData);
        }
    }
}
