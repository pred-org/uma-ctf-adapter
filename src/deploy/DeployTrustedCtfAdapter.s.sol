// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { Script } from "forge-std/Script.sol";
import { TrustedCtfAdapter } from "src/TrustedCtfAdapter.sol";

/// @title DeployTrustedCtfAdapter
/// @notice Script to deploy the TrustedCtfAdapter on Monad testnet
/// @author Polymarket
contract DeployTrustedCtfAdapter is Script {
    /// @notice Deploys the TrustedCtfAdapter
    /// @param ctfAddress - The ConditionalTokens Framework address
    /// @param admin - The admin address for the adapter
    function deploy(address ctfAddress, address admin) public returns (address adapter) {
        vm.startBroadcast();
        adapter = address(new TrustedCtfAdapter(ctfAddress, admin));
        vm.stopBroadcast();
    }

    /// @notice Deploy with default admin (msg.sender)
    /// @param ctfAddress - The ConditionalTokens Framework address
    function deployWithDefaultAdmin(address ctfAddress) public returns (address adapter) {
        vm.startBroadcast();
        adapter = address(new TrustedCtfAdapter(ctfAddress, msg.sender));
        vm.stopBroadcast();
    }
}
