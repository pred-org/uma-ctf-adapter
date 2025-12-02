#!/usr/bin/env bash

# Deploy TrustedCtfAdapter on Base Sepolia with verification
# Usage: ./scripts/deploy_trusted_adapter_base_sepolia.sh

set -e

# Source environment variables
if [ -f .env ]; then
    # shellcheck disable=SC1091
    source .env
fi

# Handle different private key variable names
if [ -n "$PRIVATE_KEY" ] && [ -z "$PK" ]; then
    PK=$PRIVATE_KEY
fi

# Validate required environment variables
if [ -z "$PK" ] && [ -z "$PRIVATE_KEY" ]; then
    echo "Error: PK or PRIVATE_KEY must be set in the environment."
    echo "Set it in .env file or export it: export PK=your_private_key"
    exit 1
fi

if [ -z "$RPC_URL" ]; then
    echo "Error: RPC_URL must be set in the environment."
    echo "Set it in .env file or export it: export RPC_URL=https://base-sepolia.g.alchemy.com/v2/your_key"
    exit 1
fi

if [ -z "$ETHERSCAN_API_KEY" ]; then
    echo "Error: ETHERSCAN_API_KEY must be set in the environment."
    echo "Set it in .env file or export it: export ETHERSCAN_API_KEY=your_basescan_api_key"
    exit 1
fi

if [ -z "$CTF_ADDRESS" ]; then
    echo "Error: CTF_ADDRESS must be set in the environment."
    echo "Set it in .env file or export it: export CTF_ADDRESS=conditional_tokens_framework_address"
    exit 1
fi

# Use PK if set, otherwise use PRIVATE_KEY
PK=${PK:-"$PRIVATE_KEY"}


echo "Deploying TrustedCtfAdapter on Base Sepolia..."
echo "Deploy args:"
echo "  ConditionalTokensFramework: $CTF_ADDRESS"
if [ -n "$ADMIN" ]; then
    echo "  Admin: $ADMIN"
    echo "  Using custom admin address"
else
    echo "  Admin: deployer (msg.sender)"
    echo "  Using deployer as admin"
fi
echo "  RPC URL: $RPC_URL"
echo "  Chain ID: $CHAIN_ID"
echo ""

# Deploy the contract
echo "Deploying contract..."
if [ -n "$ADMIN" ]; then
    OUTPUT="$(forge script DeployTrustedCtfAdapter \
        --private-key "$PK" \
        --rpc-url "$RPC_URL" \
        --json \
        --broadcast \
        -s "deploy(address,address)" "$CTF_ADDRESS" "$ADMIN")"
else
    OUTPUT="$(forge script DeployTrustedCtfAdapter \
        --private-key "$PK" \
        --rpc-url "$RPC_URL" \
        --json \
        --broadcast \
        -s "deployWithDefaultAdmin(address)" "$CTF_ADDRESS")"
fi

# Extract the deployed contract address
ADAPTER=$(echo "$OUTPUT" | grep "{" | jq -r '.returns.adapter.value // empty')
echo "TrustedCtfAdapter deployed at: $ADAPTER"

if [ -z "$ADAPTER" ] || [ "$ADAPTER" = "null" ]; then
    echo "Error: Failed to extract contract address from deployment output"
    echo "Deployment output:"
    echo "$OUTPUT"
    exit 1
fi

echo ""
echo "Waiting for transaction to be mined..."

# Wait a bit for the transaction to be mined
sleep 15

# Verify the contract
echo "Verifying contract on Base Sepolia..."
VERIFY_OUTPUT="$(forge verify-contract \
    "$ADAPTER" \
    src/TrustedCtfAdapter.sol:TrustedCtfAdapter \
    --chain "$CHAIN_ID" \
    --etherscan-api-key "$ETHERSCAN_API_KEY" \
    --watch)"

echo "$VERIFY_OUTPUT"

if echo "$VERIFY_OUTPUT" | grep -q "Contract successfully verified"; then
    echo ""
    echo "✅ Deployment and verification completed successfully!"
    echo "Contract address: $ADAPTER"
    echo "View on Base Sepolia Explorer: $EXPLORER_URL/address/$ADAPTER"
else
    echo ""
    echo "⚠️  Contract deployed but verification may have failed."
    echo "Contract address: $ADAPTER"
    echo "You can try verifying manually with:"
    echo "forge verify-contract $ADAPTER src/TrustedCtfAdapter.sol:TrustedCtfAdapter --chain $CHAIN_ID --etherscan-api-key $ETHERSCAN_API_KEY"
fi

echo ""
echo "Deployment complete!"
