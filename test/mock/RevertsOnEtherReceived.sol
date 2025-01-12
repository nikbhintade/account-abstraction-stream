// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.24;

contract RevertsOnEtherReceived {
    receive() external payable {
        revert("revert on receiving ether");
    }
}
