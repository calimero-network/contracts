#!/bin/bash
set -ex

cd "$(dirname $0)"

# Install dependencies
forge install --no-commit foundry-rs/forge-std

# Build using forge with zksync flag
forge build --zksync