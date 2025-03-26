#!/bin/bash

# Builds all solidity components of the project
# This script is intended to be run from the root of the project

# Exit immediately if a command exits with a non-zero status.
set -ex

# Build contracts
contracts/ethereum/context-config/build.sh
contracts/ethereum/context-proxy/build_contracts.sh
