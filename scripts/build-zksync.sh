#!/bin/bash

# Builds all ZKsync solidity components of the project
# This script is intended to be run from the root of the project

# Exit immediately if a command exits with a non-zero status.
set -ex

# Build contracts
contracts/zksync/context-config/build.sh
contracts/zksync/context-proxy/build_contracts.sh 