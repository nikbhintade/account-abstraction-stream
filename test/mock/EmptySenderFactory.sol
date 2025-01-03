// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.24;

contract EmptySenderFactory {
    address private acAddress;

    constructor() {
        acAddress = address(bytes20(keccak256("generateEmptySender")));
    }

    function getAccountAddress() public view returns(address){
        return acAddress;
    }
    function createAccount(address entryPoint, address owner, bytes32 salt) public view returns(address) {
        (entryPoint, owner, salt);
        return acAddress;
    }

}