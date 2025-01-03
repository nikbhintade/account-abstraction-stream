// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {AccountFactory} from "src/samples/AccountFactory.sol";
import {SimpleAccount} from "src/samples/SimpleAccount.sol";
import {EntryPoint} from "src/core/EntryPoint.sol";

contract AccountFactoryTest is Test {
    AccountFactory private accountFactory;
    EntryPoint private entryPoint;
    address private owner;

    function setUp() public {
        accountFactory = new AccountFactory();
        entryPoint = new EntryPoint();
        owner = makeAddr("owner");
    }

    function testAccountFactoryIsCreatedOnCreateAddress() public {
        bytes32 salt = keccak256(abi.encodePacked("random-string"));
        bytes32 byteCodeHash = keccak256(abi.encodePacked(type(SimpleAccount).creationCode, abi.encode(entryPoint, owner)));
        address expectedAddress = accountFactory.getAccountAddress(salt, byteCodeHash);

        address generatedAddress = accountFactory.createAccount(address(entryPoint), owner, salt);

        assertEq(expectedAddress, generatedAddress);

        bytes memory callData = abi.encodeWithSelector(SimpleAccount.entryPoint.selector);
        (bool success, bytes memory data) = generatedAddress.call(callData);

        require(success, "something went wrong");
        
        address actualEntryPoint = abi.decode(data, (address));

        assertEq(address(entryPoint), actualEntryPoint);
    }
}
