import "@matterlabs/hardhat-zksync-deploy";
import "@matterlabs/hardhat-zksync-solc";
import "@matterlabs/hardhat-zksync-verify";

import { HardhatUserConfig } from "hardhat/config";

const config: HardhatUserConfig = {
  zksolc: {
    version: "1.3.14",
    compilerSource: "binary",
    settings: {
      isSystem: true,
      optimizer: {
        enabled: true,
        mode: "3",
      },
    },
  },
  defaultNetwork: "zkSyncTestnet",
  networks: {
    hardhat: {
      zksync: true,
    },
    zkSyncTestnet: {
      url: "https://zksync2-testnet.zksync.dev",
      ethNetwork: "goerli",
      zksync: true,
      verifyURL: "https://zksync2-testnet-explorer.zksync.dev/contract_verification",
      gasPrice: "auto",
      gas: "auto",
    },
    zkSyncMainnet: {
      url: "https://mainnet.era.zksync.io",
      ethNetwork: "mainnet",
      zksync: true,
      verifyURL: "https://zksync2-mainnet-explorer.zksync.dev/contract_verification",
      gasPrice: "auto",
      gas: "auto",
    },
  },
  solidity: {
    version: "0.8.17",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
        details: {
          yul: true,
          yulDetails: {
            stackAllocation: true,
            optimizerSteps: "dhfoDgvulfnTUtnIf"
          },
        },
      },
      viaIR: true,
    },
  },
};

export default config; 