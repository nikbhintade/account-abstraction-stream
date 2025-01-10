// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.24;

import {UserOperationLibHarness} from "test/harnesses/UserOperationLibHarness.sol";
import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";
import {Test} from "forge-std/Test.sol";

contract UserOperationLibTest is Test {
    UserOperationLibHarness private uolh;

    function setUp() public {
        uolh = new UserOperationLibHarness();
    }

    function testAllFunctionsOfLib() public {
        address sender = makeAddr("sender");
        uint256 nonce = 1_000;
        bytes memory initCode = abi.encode("generate random initCode value");
        bytes memory callData = abi.encode("generate random callData value");
        uint256 verificationGasLimit = 100_000;
        uint256 callGasLimit = 200_000;
        uint256 preVerificationGas = 50_000;
        uint256 maxFeePerGas = 20;
        uint256 maxPriorityFee = 40;
        
        address paymaster = makeAddr("paymaster");
        uint256 paymasterVerificationGasLimit = 45_000;
        uint256 paymasterPostOpGasLimit = 90_000;

        bytes memory signature = abi.encodePacked("generate random signature value");

        PackedUserOperation memory userOp = PackedUserOperation({
            sender:sender, 
            nonce: nonce,
            initCode: initCode,
            callData: callData,
            accountGasLimits: bytes32(verificationGasLimit << 128 | callGasLimit), 
            preVerificationGas: preVerificationGas,
            gasFees: bytes32(maxFeePerGas << 128 | maxPriorityFee),
            paymasterAndData: abi.encode(paymaster, paymasterVerificationGasLimit, paymasterPostOpGasLimit),
            signature: signature
        });

        // getSender
        // gasPrice
        // encode

        // unpackMaxPriorityFeePerGas
        // unpackMaxFeePerGas
        // unpackVerificationGasLimit
        // unpackCallGasLimit
        // unpackPaymasterVerificationGasLimit
        // unpackPostOpGasLimit
        // unpackPaymasterStaticFields
        // hash
    }
}
