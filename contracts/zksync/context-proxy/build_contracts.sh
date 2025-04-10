#!/bin/bash
set -ex

cd "$(dirname "$0")"

# Build proxy contract
./build.sh

# Build mock contract
mock/build.sh
