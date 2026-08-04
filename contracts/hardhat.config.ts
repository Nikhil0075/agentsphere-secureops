import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import * as dotenv from "dotenv";
import * as path from "path";

// The repo-level .env is the single source of configuration; the deployer key lives there and
// nowhere else. It is git-ignored.
dotenv.config({ path: path.resolve(__dirname, "..", ".env") });

const DEPLOYER_PRIVATE_KEY = process.env.DEPLOYER_PRIVATE_KEY ?? "";

// A keyless public endpoint by default, so a deployment is not gated on signing up for an RPC
// provider. Override with SEPOLIA_RPC_URL for anything sustained.
const SEPOLIA_RPC_URL =
  process.env.SEPOLIA_RPC_URL ?? "https://ethereum-sepolia-rpc.publicnode.com";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
    },
  },
  networks: {
    hardhat: {
      chainId: 31337,
    },
    localhost: {
      url: "http://127.0.0.1:8545",
      chainId: 31337,
    },
    sepolia: {
      url: SEPOLIA_RPC_URL,
      chainId: 11155111,
      accounts: DEPLOYER_PRIVATE_KEY ? [DEPLOYER_PRIVATE_KEY] : [],
    },
  },
  etherscan: {
    // Optional. Source verification needs a free key; the deployment works without one.
    apiKey: process.env.ETHERSCAN_API_KEY ?? "",
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS === "true",
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },
};

export default config;
