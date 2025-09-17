# TrustedCtfAdapter Deployment on Monad Testnet

This guide explains how to deploy the TrustedCtfAdapter contract on Monad testnet with automatic verification.

## Prerequisites

1. **Environment Setup**: Make sure you have Foundry installed
2. **Private Key**: Your private key for deployment (without 0x prefix)
3. **Monad Testnet Access**: Ensure you can connect to Monad testnet

## Quick Start

1. **Copy environment file**:
   ```bash
   cp .env.example .env
   ```

2. **Edit `.env` file** with your values:
   ```bash
   # Required
   PK=your_private_key_here
   RPC_URL=https://testnet-rpc.monad.xyz
   
   # Optional (defaults to deployer if not set)
   ADMIN=0x1234567890123456789012345678901234567890
   ```

3. **Deploy the contract**:
   ```bash
   ./scripts/deploy_trusted_adapter_monad.sh
   ```

## Manual Deployment

If you prefer to deploy manually:

```bash
# Deploy with custom admin
forge script DeployTrustedCtfAdapter \
    --private-key $PK \
    --rpc-url $RPC_URL \
    --broadcast \
    -s "deploy(address,address)" 0x52CD9f25AFcc9D007F72431842F811E8F21EE75F $ADMIN

# Deploy with deployer as admin
forge script DeployTrustedCtfAdapter \
    --private-key $PK \
    --rpc-url $RPC_URL \
    --broadcast \
    -s "deployWithDefaultAdmin(address)" 0x52CD9f25AFcc9D007F72431842F811E8F21EE75F
```

## Manual Verification

If automatic verification fails, you can verify manually:

```bash
forge verify-contract \
    <CONTRACT_ADDRESS> \
    src/TrustedCtfAdapter.sol:TrustedCtfAdapter \
    --chain 10143 \
    --verifier sourcify \
    --verifier-url https://sourcify-api-monad.blockvision.org
```

## Contract Details

- **Contract**: TrustedCtfAdapter
- **CTF Address**: 0x52CD9f25AFcc9D007F72431842F811E8F21EE75F
- **Chain ID**: 10143 (Monad Testnet)
- **Explorer**: https://testnet-explorer.monad.xyz

## Roles

- **DEFAULT_ADMIN_ROLE**: Can initialize markets and manage roles
- **RESOLVER_ROLE**: Can resolve markets (admin gets this role by default)

## Functions

- `initialize(questionId, outcomeSlotCount)`: Prepare a new market
- `resolveWithIndex(questionId, winningIdx)`: Resolve with winner index
- `resolveInvalid(questionId)`: Resolve as invalid (equal payouts)
- `resolveWithVector(questionId, payoutNumerators)`: Resolve with custom payouts
