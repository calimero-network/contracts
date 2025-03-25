#!/bin/bash
set -ex

cd "$(dirname $0)"

# Install dependencies first
forge install foundry-rs/forge-std --no-commit

# Then build
forge build
