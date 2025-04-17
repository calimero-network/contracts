#!/bin/bash
set -ex

cd "$(dirname $0)"

# Set shell type to bash for the installation
export SHELL=bash

echo "OK"
# Install zkSync Foundry toolkit
curl -L https://raw.githubusercontent.com/matter-labs/foundry-zksync/main/install-foundry-zksync | bash

echo "OK"
# Ensure PATH is set correctly
export PATH="$HOME/.foundry/bin:$PATH"
echo "OK"

# Then build
forge --zksync build
