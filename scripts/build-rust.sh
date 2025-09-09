#!/bin/bash

# Builds all rust components of the project
# This script is intended to be run from the root of the project

# Exit immediately if a command exits with a non-zero status.
set -ex

# Build contracts
contracts/near/registry/build.sh
contracts/near/context-config/build.sh
contracts/near/context-proxy/build-test-deps.sh
contracts/icp/context-config/build.sh
contracts/icp/context-proxy/build_contracts.sh

cargo build --all-targets --tests
