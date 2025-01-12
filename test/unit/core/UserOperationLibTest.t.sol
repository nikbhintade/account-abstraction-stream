// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.24;

import {UserOperationLibHarness} from "test/harnesses/UserOperationLibHarness.sol";
import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";
import {Test, console2 as console} from "forge-std/Test.sol";

contract UserOperationLibTest is Test {
    UserOperationLibHarness private uolh;

    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 verificationGasLimit;
    uint256 callGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFee;
    address paymaster;
    uint256 paymasterVerificationGasLimit;
    uint256 paymasterPostOpGasLimit;
    bytes signature;
    PackedUserOperation userOp;

    function setUp() public {
        uolh = new UserOperationLibHarness();
        sender = makeAddr("sender");
        nonce = 1_000;
        initCode = abi.encode("generate random initCode value");
        callData = abi.encode("generate random callData value");
        verificationGasLimit = 100_000;
        callGasLimit = 200_000;
        preVerificationGas = 50_000;
        maxFeePerGas = 40;
        maxPriorityFee = 20;

        paymaster = makeAddr("paymaster");
        paymasterVerificationGasLimit = 45_000;
        paymasterPostOpGasLimit = 90_000;

        signature = abi.encodePacked("generate random signature value");

        userOp = PackedUserOperation({
            sender: sender,
            nonce: nonce,
            initCode: initCode,
            callData: callData,
            accountGasLimits: bytes32(verificationGasLimit << 128 | callGasLimit),
            preVerificationGas: preVerificationGas,
            gasFees: bytes32(maxPriorityFee << 128 | maxFeePerGas),
            paymasterAndData: abi.encodePacked(
                paymaster, uint128(paymasterVerificationGasLimit), uint128(paymasterPostOpGasLimit)
            ),
            signature: signature
        });
    }

    function testAllFunctionsOfLib() public {
        // getSender
        assertEq(uolh.getSender(userOp), sender);
        // gasPrice
        assertEq(uolh.gasPrice(userOp), maxPriorityFee);
        // encode
        bytes memory encodedData = abi.encode(
            sender,
            nonce,
            keccak256(initCode),
            keccak256(callData),
            bytes32(verificationGasLimit << 128 | callGasLimit),
            preVerificationGas,
            bytes32(maxPriorityFee << 128 | maxFeePerGas),
            keccak256(
                abi.encodePacked(paymaster, uint128(paymasterVerificationGasLimit), uint128(paymasterPostOpGasLimit))
            )
        );
        assertEq(uolh.encode(userOp), encodedData);

        // unpackMaxPriorityFeePerGas
        assertEq(uolh.unpackMaxPriorityFeePerGas(userOp), maxPriorityFee);
        // unpackMaxFeePerGas
        assertEq(uolh.unpackMaxFeePerGas(userOp), maxFeePerGas);
        // unpackVerificationGasLimit
        assertEq(uolh.unpackVerificationGasLimit(userOp), verificationGasLimit);
        // unpackCallGasLimit
        assertEq(uolh.unpackCallGasLimit(userOp), callGasLimit);
        // unpackPaymasterVerificationGasLimit
        assertEq(uolh.unpackPaymasterVerificationGasLimit(userOp), paymasterVerificationGasLimit);
        // unpackPostOpGasLimit
        assertEq(uolh.unpackPostOpGasLimit(userOp), paymasterPostOpGasLimit);
        // unpackPaymasterStaticFields
        (address retPaymaster, uint256 retVerificationPaymaster, uint256 retPostOp) =
            uolh.unpackPaymasterStaticFields(userOp.paymasterAndData);
        assertEq(
            keccak256(abi.encodePacked(retPaymaster, uint128(retVerificationPaymaster), uint128(retPostOp))),
            keccak256(
                abi.encodePacked(paymaster, uint128(paymasterVerificationGasLimit), uint128(paymasterPostOpGasLimit))
            )
        );
        // hash
        assertEq(uolh.hash(userOp), keccak256(encodedData));

        userOp.gasFees = bytes32(uint256(20) << 128 | uint256(20));
        assertEq(uolh.gasPrice(userOp), maxPriorityFee);
    }
}
