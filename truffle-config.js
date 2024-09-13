const HDWalletProvider = require('@truffle/hdwallet-provider');
require('dotenv').config();

const DEPLOYER_KEY = process.env.DEPLOYER_KEY;
const POLYSCANAPIKEY = process.env.POLYSCANAPIKEY;

module.exports = {
  plugins: [
    'truffle-plugin-verify'
  ],
  api_keys: {
    polygonscan: POLYSCANAPIKEY
  },
  dashboard: {
    port: 24012,
  },
  networks: {
    development: {
      host: "127.0.0.1",     // Localhost (default: none)
      port: 8545,            // Standard BSC port (default: none)
      network_id: "*",       // Any network (default: none)
    },
    mumbai: {
      provider: () => new HDWalletProvider(DEPLOYER_KEY, `https://matic.getblock.io/aab69b85-dd39-4b1c-ae14-50197345a895/testnet/`),
      network_id: 80001,
      confirmations: 5,
      timeoutBlocks: 600,
      gas: 20000000,
      gasPrice: 50000000000,
      skipDryRun: false,
      networkCheckTimeout: 50000,
      disableConfirmationListener: true
    },
    amoy: {
      provider: () => new HDWalletProvider(DEPLOYER_KEY, `https://rpc-amoy.polygon.technology`),
      network_id: 80002,
      confirmations: 5,
      timeoutBlocks: 600,
      gas: 20000000,
      gasPrice: 50000000000,
      skipDryRun: false,
      networkCheckTimeout: 50000,
      disableConfirmationListener: true
    },
    matic: {
      provider: () => new HDWalletProvider(DEPLOYER_KEY, `https://polygon-rpc.com`),
      network_id: 137,
      confirmations: 2,
      gasPrice: 50000000000,
      timeoutBlocks: 200,
      skipDryRun: true
		},
    zkevmTest: {
      provider: () => new HDWalletProvider(DEPLOYER_KEY, `https://rpc.public.zkevm-test.net`),
      network_id: 1442,
      confirmations: 2,
      gasPrice: 50000000000,
      timeoutBlocks: 200,
      skipDryRun: true
		},
    zkevm: {
      provider: () => new HDWalletProvider(DEPLOYER_KEY, `https://rpc.ankr.com/polygon_zkevm`),
      network_id: 1101,
      confirmations: 2,
      gasPrice: 50000000000,
      timeoutBlocks: 200,
      skipDryRun: true
		},
    dashboard: {
      port: 25012,
      host: "localhost"
    }
  },
  // Set default mocha options here, use special reporters etc.
  mocha: {
    // timeout: 100000
  },

  // Configure your compilers
  compilers: {
    solc: {
      //https://forum.openzeppelin.com/t/how-to-deploy-uniswapv2-on-ganache/3885
      version: "0.8.20", // last > 0.8.16 // uni > 0.8.4 // "0.8.0", // "0.6.12",    // Fetch exact version from solc-bin (default: truffle's version)
      // docker: true,        // Use "0.5.1" you've installed locally with docker (default: false)
      settings: {          // See the solidity docs for advice about optimization and evmVersion
        optimizer: {
          enabled: true,
          runs: 200 // 2000
        },
      }
    },
  }
}