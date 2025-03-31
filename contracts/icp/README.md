## Calimero ICP Contracts

Smart contracts for the Calimero Internet Computer Protocol (ICP) implementation.

This repository contains:
- **Context Config**: Factory contract for creating and managing contexts
- **Context Proxy**: Multi-signature contract implementation
- **Mock**: Test contracts for integration testing

## Development Tools

Required tools:
- **dfx**: ICP development toolkit ([installation guide](https://internetcomputer.org/docs/current/developer-docs/setup/install/))
- **candid-extractor**: For Candid interface generation
- **Rust**: For contract compilation

Note: The development environment uses dfx version 0.24.3

## Development Workflow

### Building Contracts

Each contract has its own build script:

```shell
# Build Context Config
$ cd context-config
$ ./build.sh

# Build Context Proxy
$ cd ../context-proxy
$ ./build.sh

# Build Mock contracts
$ cd context-proxy/mock
$ ./build.sh
```

Each build script will:
1. Add wasm32-unknown-unknown target if not present
2. Compile the contract with app-release profile
3. Generate Candid interface (if candid-extractor is available)
4. Artifacts are automatically placed in the `res` directory

### Local Development

To spin up a local devnet with all contracts deployed:

```shell
$ cd context-config
$ ./deploy_devnet.sh
```

This will:
1. Check for required dependencies (dfx, cargo, candid-extractor)
2. Set up dfx identities for testing (minting, initial, archive, recipient)
3. Start a clean dfx instance
4. Deploy and configure:
   - Context Contract
   - Ledger Canister
   - Mock External Contract
5. Set up the proxy code

Example output:

```
=== Deployment Summary ===
Context Contract ID: ${CONTEXT_ID}
Ledger Contract ID: ${LEDGER_ID}
Account Information:
Minting Account: ${MINTING_ACCOUNT}
Initial Account: ${INITIAL_ACCOUNT}
Archive Principal: ${ARCHIVE_PRINCIPAL}
Recipient Principal: ${RECIPIENT_PRINCIPAL}
Mock External Contract ID: ${MOCK_EXTERNAL_ID}
Deployment completed successfully!
```

### Testing

Run tests for each contract in its respective directory:

```shell
$ cd context-config
$ cargo test

$ cd ../context-proxy
$ cargo test
```

For verbose output:
```shell
$ cargo test -- --nocapture
```
