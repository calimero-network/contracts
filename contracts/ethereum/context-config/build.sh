#!/bin/bash
set -ex

cd "$(dirname $0)"

# Install dependencies first
forge install --no-git foundry-rs/forge-std

# Then build
forge build
