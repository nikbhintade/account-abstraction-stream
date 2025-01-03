// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/utils/Create2.sol";
import {SimpleAccount} from "src/samples/SimpleAccount.sol";
import {IEntryPoint} from "src/interfaces/IEntryPoint.sol";

contract AccountFactory {
    function createAccount(address entryPoint, address owner, bytes32 salt) public returns (address) {
        bytes memory creationCode = abi.encodePacked(type(SimpleAccount).creationCode, abi.encode(IEntryPoint(entryPoint), owner));
        return Create2.deploy(0, salt, creationCode);
    }

    function getAccountAddress(bytes32 salt, bytes32 byteCodeHash) public view returns (address) {
        return Create2.computeAddress(salt, byteCodeHash);
    }
}
