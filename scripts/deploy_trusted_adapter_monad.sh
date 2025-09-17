#!/usr/bin/env bash

# Deploy TrustedCtfAdapter on Monad testnet with verification
# Usage: ./scripts/deploy_trusted_adapter_monad.sh

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
    echo "  PK=your_private_key (or PRIVATE_KEY)"
    echo "  RPC_URL=https://testnet-rpc.monad.xyz"
    echo "  ADMIN=admin_address (optional, defaults to deployer)"
    exit 1
fi

# Set default values
CTF_ADDRESS=${CTF_ADDRESS:-"0x52CD9f25AFcc9D007F72431842F811E8F21EE75F"}
ADMIN=${ADMIN:-""}

echo "Deploying TrustedCtfAdapter on Monad testnet..."
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
echo ""

# Deploy the contract
echo "Deploying contract..."
if [ -n "$ADMIN" ]; then
    OUTPUT="$(forge script DeployTrustedCtfAdapter \
        --private-key $PK \
        --rpc-url $RPC_URL \
        --json \
        --broadcast \
        -s "deploy(address,address)" $CTF_ADDRESS $ADMIN)"
else
    OUTPUT="$(forge script DeployTrustedCtfAdapter \
        --private-key $PK \
        --rpc-url $RPC_URL \
        --json \
        --broadcast \
        -s "deployWithDefaultAdmin(address)" $CTF_ADDRESS)"
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
sleep 10

# Verify the contract
echo "Verifying contract on Monad Explorer..."
VERIFY_OUTPUT="$(forge verify-contract \
    $ADAPTER \
    src/TrustedCtfAdapter.sol:TrustedCtfAdapter \
    --chain 10143 \
    --verifier sourcify \
    --verifier-url https://sourcify-api-monad.blockvision.org \
    --watch)"

echo "$VERIFY_OUTPUT"

if echo "$VERIFY_OUTPUT" | grep -q "Contract successfully verified"; then
    echo ""
    echo "✅ Deployment and verification completed successfully!"
    echo "Contract address: $ADAPTER"
    echo "View on Monad Explorer: https://testnet-explorer.monad.xyz/address/$ADAPTER"
else
    echo ""
    echo "⚠️  Contract deployed but verification may have failed."
    echo "Contract address: $ADAPTER"
    echo "You can try verifying manually with:"
    echo "forge verify-contract $ADAPTER src/TrustedCtfAdapter.sol:TrustedCtfAdapter --chain 10143 --verifier sourcify --verifier-url https://sourcify-api-monad.blockvision.org"
fi

echo ""
echo "Deployment complete!"
