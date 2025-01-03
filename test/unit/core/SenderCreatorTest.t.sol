// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {SenderCreator} from "src/core/SenderCreator.sol";

contract RevertingFactory {
    function revertOnCall() public pure {
        revert();
    }
}

contract SenderCreatorTest is Test {
    SenderCreator private senderCreator;
    RevertingFactory private revertingFactory;

    function setUp() public {
        senderCreator = new SenderCreator();
        revertingFactory = new RevertingFactory();
    }

    function testCreateSenderReturnsZeroAddressOnFailedCall() public {

        bytes memory callData = abi.encodePacked(address(revertingFactory), abi.encodeWithSelector(RevertingFactory.revertOnCall.selector));
        
        address expectedSender = address(0);
        address actualSender = senderCreator.createSender(callData);

        assertEq(expectedSender, actualSender);
    }
}
