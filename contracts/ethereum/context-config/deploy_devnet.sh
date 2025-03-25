#!/bin/bash
set -e

# Define variables
RPC_URL="http://localhost:8545"
PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Anvil's deterministic addresses
DEPLOYER_ADDRESS="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
CONTEXT_CONFIG_ADDRESS="0x5FbDB2315678afecb367f032d93F642f64180aa3"
MOCK_CONTRACT_ADDRESS="0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"

# Get absolute paths
cd ..  # Move up to project root
PROJECT_ROOT=$(pwd)
CONFIG_DIR="$PROJECT_ROOT/context-config"
PROXY_DIR="$PROJECT_ROOT/context-proxy"
MOCK_DIR="$PROJECT_ROOT/context-proxy/mock"

# Start Anvil
start_anvil() {
    echo "Starting Anvil..."
    anvil --host 0.0.0.0 --port 8545 &
    ANVIL_PID=$!
    sleep 3
    trap "echo 'Shutting down Anvil...'; kill $ANVIL_PID" EXIT
}

# Deploy contracts
deploy_contracts() {
    # Deploy ContextConfig
    CONFIG_BYTECODE=$(jq -r .bytecode "$CONFIG_DIR/out/ContextConfig.sol/ContextConfig.json")
    cast send --create --bytecode "$CONFIG_BYTECODE" --private-key $PRIVATE_KEY --rpc-url $RPC_URL
    echo "ContextConfig deployed at: $CONTEXT_CONFIG_ADDRESS"
    
    # Get and set ContextProxy bytecode
    PROXY_BYTECODE=$(jq -r .bytecode "$PROXY_DIR/out/ContextProxy.sol/ContextProxy.json")
    cast send $CONTEXT_CONFIG_ADDRESS "setProxyCode(bytes)" "$PROXY_BYTECODE" --private-key $PRIVATE_KEY --rpc-url $RPC_URL
    echo "Proxy code set in ContextConfig"
    
    # Deploy MockExternalContract
    MOCK_BYTECODE=$(jq -r .bytecode "$MOCK_DIR/out/MockExternalContract.sol/MockExternalContract.json")
    cast send --create --bytecode "$MOCK_BYTECODE" --private-key $PRIVATE_KEY --rpc-url $RPC_URL
    echo "MockExternalContract deployed at: $MOCK_CONTRACT_ADDRESS"
}

# Main execution
echo "Starting deployment process..."
start_anvil
deploy_contracts
echo "Deployment completed successfully!"
echo "Anvil is running. Press Ctrl+C to stop."
wait $ANVIL_PID