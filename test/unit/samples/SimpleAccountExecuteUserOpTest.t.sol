// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {SimpleAccountExecuteUserOp} from "src/samples/SimpleAccountExecuteUserOp.sol";
import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";
import {EntryPoint} from "src/core/EntryPoint.sol";

contract SimpleAccountExecuteUserOpTest is Test {
    SimpleAccountExecuteUserOp private simpleAccount;
    EntryPoint private entryPoint;
    Account private owner;

    function setUp() public {
        entryPoint = new EntryPoint();
        owner = makeAccount("owner");
        simpleAccount = new SimpleAccountExecuteUserOp(entryPoint, owner.addr);
    }
}
