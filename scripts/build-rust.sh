#!/bin/bash

# Builds all rust components of the project
# This script is intended to be run from the root of the project

# Exit immediately if a command exits with a non-zero status.
set -euo pipefail

# Build contracts
contracts/near/registry/build.sh
contracts/near/context-config/build.sh
contracts/near/context-proxy/build-test-deps.sh

RUSTFLAGS="--remap-path-prefix $HOME=~" cargo build --all-targets --tests \
  -p calimero-registry \
  -p calimero-context-config-near \
  -p calimero-context-proxy-near \
  -p calimero-mock-external-near
