# PRED CTF Adapter

## Overview

This repository contains contracts used to resolve PRED prediction markets via PRED's centralised Oracle.

## Architecture
![Contract Architecture](./docs/adapter.png)

The Adapter is an [oracle](https://github.com/pred-org/conditional-tokens-contracts/blob/a927b5a52cf9ace712bf1b5fe1d92bf76399e692/contracts/ConditionalTokens.sol#L65) to [Conditional Tokens Framework(CTF)](https://docs.gnosis.io/conditionaltokens/) conditions, which PRED prediction markets are based on.

It fetches resolution data from PRED's centralized Oracle and resolves the condition based on said resolution data.

When a new market is deployed, it is `initialized`, meaning:
1) The market's parameters(ancillary data, request timestamp, reward token, reward, etc) are stored onchain
2) The market is [`prepared`](https://github.com/pred-org/conditional-tokens-contracts/blob/a927b5a52cf9ace712bf1b5fe1d92bf76399e692/contracts/ConditionalTokens.sol#L65) on the CTF contract
3) A resolution data request is sent out to PRED's centralized Oracle

PRED's centralized Oracle will process the request and provide resolution data. Once the resolution data is available, anyone can call `resolve` which resolves the market using the resolution data.


## Audit 

These contracts have been audited by OpenZeppelin and the report is available [here](./audit/Polymarket_UMA_Optimistic_Oracle_Adapter_Audit.pdf).

## Deployments

See [Deployments](https://github.com/pred-org/uma-ctf-adapter/releases)


## Development

Clone the repo: `git clone https://github.com/pred-org/uma-ctf-adapter.git --recurse-submodules`

---

### Set-up

Install [Foundry](https://github.com/foundry-rs/foundry/).

Foundry has daily updates, run `foundryup` to update `forge` and `cast`.

To install/update forge dependencies: `forge update`

To build contracts: `forge build`

---

### Testing

To run all tests: `forge test`

Set `-vvv` to see a stack trace for a failed test.