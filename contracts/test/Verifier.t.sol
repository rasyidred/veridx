// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Halo2Verifier} from "../src/Verifier.sol";

contract VerifierTest is Test {
    Halo2Verifier verifier;
    bytes proofCalldata; // selector + proof + instances, from ezkl.encode_evm_calldata

    function setUp() public {
        verifier = new Halo2Verifier();
        proofCalldata = vm.readFileBinary("../artifacts/calldata.bytes");
    }

    function test_ValidProof() public {
        (bool ok, bytes memory ret) = address(verifier).call(proofCalldata);
        assertTrue(ok);
        assertTrue(abi.decode(ret, (bool)));
    }

    function test_TamperedOutputReverts() public {
        bytes memory bad = proofCalldata; // storage -> memory copy
        uint256 instOffset = word(bad, 36); // offset of the instances array (after the selector)
        uint256 n = word(bad, 4 + instOffset); // number of public instances
        assertEq(n, 31); // 30 inputs + 1 output

        bad[4 + instOffset + 32 * n + 31] ^= 0x01; // last byte of the output instance
        (bool ok,) = address(verifier).call(bad);
        assertFalse(ok);
    }

    function word(bytes memory b, uint256 i) internal pure returns (uint256 r) {
        assembly {
            r := mload(add(add(b, 32), i))
        }
    }
}
