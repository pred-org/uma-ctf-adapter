#!/usr/bin/env bash

# Deploy TrustedCtfAdapter on Base Sepolia with verification
# Usage: ./scripts/deploy_trusted_adapter_base_sepolia.sh

set -e

# Source environment variables
if [ -f .env ]; then
    source .env
    # Handle different private key variable names
    if [ -n "$PRIVATE_KEY" ] && [ -z "$PK" ]; then
        PK=$PRIVATE_KEY
    fi
else
    echo "Error: .env file not found. Please create one with the required variables."
    echo "Required variables:"
    echo "  PRIVATE_KEY=your_private_key"
    echo "  RPC_URL=https://base-sepolia.g.alchemy.com/v2/your_key"
    echo "  ETHERSCAN_API_KEY=your_etherscan_api_key"
    exit 1
fi

# Set Base Sepolia specific values
CTF_ADDRESS="0xb04639fB29CC8D27e13727c249EbcAb0CDA92331"
ADMIN="0x7496014dd7ec0C825c3BC1e91bd5C01E2961318B"
CHAIN_ID="84532"  # Base Sepolia chain ID

echo "Deploying TrustedCtfAdapter on Base Sepolia..."
echo "Deploy args:"
echo "  ConditionalTokensFramework: $CTF_ADDRESS"
echo "  Admin: $ADMIN"
echo "  RPC URL: $RPC_URL"
echo "  Chain ID: $CHAIN_ID"
echo ""

# Deploy the contract
echo "Deploying contract..."
OUTPUT="$(forge script DeployTrustedCtfAdapter \
    --private-key $PK \
    --rpc-url $RPC_URL \
    --json \
    --broadcast \
    -s "deploy(address,address)" $CTF_ADDRESS $ADMIN)"

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
    $ADAPTER \
    src/TrustedCtfAdapter.sol:TrustedCtfAdapter \
    --chain $CHAIN_ID \
    --etherscan-api-key $ETHERSCAN_API_KEY \
    --watch)"

echo "$VERIFY_OUTPUT"

if echo "$VERIFY_OUTPUT" | grep -q "Contract successfully verified"; then
    echo ""
    echo "✅ Deployment and verification completed successfully!"
    echo "Contract address: $ADAPTER"
    echo "View on Base Sepolia Explorer: https://sepolia.basescan.org/address/$ADAPTER"
else
    echo ""
    echo "⚠️  Contract deployed but verification may have failed."
    echo "Contract address: $ADAPTER"
    echo "You can try verifying manually with:"
    echo "forge verify-contract $ADAPTER src/TrustedCtfAdapter.sol:TrustedCtfAdapter --chain $CHAIN_ID --etherscan-api-key $ETHERSCAN_API_KEY"
fi

echo ""
echo "Deployment complete!"
