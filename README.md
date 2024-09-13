# TXMonitor Smart Contract

The TXMonitor Smart Contract is designed to monitor and manage token transfers on the Ethereum Virtual Machine (EVM) blockchain. It includes functionality to track transactions using events, allowing developers to monitor deposits, withdrawals, and token transfers.

## Features

- **Deposit and Withdrawal Monitoring:** The contract emits events for deposits and withdrawals, providing transparency and auditability for token movements for external platforms.
  
- **Token Transfer Tracking:** Developers can use the contract's events to track token transfers between addresses, ensuring visibility into token flow.

- **Configurable Owner Wallet:** The contract allows setting the owner wallet address, providing flexibility in managing contract ownership and access.

## Usage

1. **Deploy the Contract:**


  - **Compile the Contract:**
     ```bash
     truffle compile
     ```
     This command compiles your Solidity smart contract, ensuring it is ready for deployment.

   - **Configure Deployment Parameters:**
     Before deploying the contract, ensure you have configured the following parameters on migration file 1_deployMonitorSC:
     - USDT Token Contract Address: Specify the address of the USDT token contract if applicable, required for token operations within the TXMonitor contract.
     - BussinessId , is an alpha-numeric code of ten (10) digits, with only capital letters and numbers, BUID is created and submitted as a parameter by you. For example: MERCA12345

   - **Deploy Using Truffle:**
     Use Truffle's migration scripts to deploy the contract to your desired Ethereum network. For example, to deploy on the Mumbai testnet:
     ```bash
     truffle migrate --network mumbai
     ```
     Replace `mumbai` with the network name you intend to deploy to.

     Or use

     ```bash
     truffle migrate --network dashboard
     ```
   
     to run directly with injected wallet in browser on truffle dashboard


   - **Verify Deployment:**
     After successful deployment, verify the contract address and confirm that the contract is deployed to the correct network.
     
     ```bash
     npx truffle run verify TXMonitor --network dashboard (or network used)
     ```


   - **Transaction Monitoring:**
     Once deployed, you can start monitoring transactions using the events emitted by the contract. Events such as `Deposit`, `Withdraw`, and `TokensWithdraw` provide insights into token movements and contract interactions.


2. **Monitor Transactions:**
   - Use the `transfer` function to transfer tokens between addresses, which emits `Deposit` and `Withdraw` events based on the transaction type choose 0 for Deposit and 1 for Withdraw.
   - Listen for events using the Web3.js library or other Ethereum-compatible libraries to track deposits, withdrawals, and token transfers.

3. **Owner Wallet Management:**
   - The contract includes functions to update the owner wallet address and the USDT token contract address, providing control over contract ownership and token management.

## Events

The contract emits the following events:

- **Deposit:** Emits when calling 'transfer' using txtype 0 for when you are tracking deposits.
  - Parameters: `senderWallet`, `receiverWallet`, `amount`, `message`, `msgId`, `encrypt`

- **Withdraw:** Emits when calling 'transfer' using txtype 1 for when you are tracking withdraws.
  - Parameters: `senderWallet`, `receiverWallet`, `amount`, `message`, `msgId`, `encrypt`

- **TokensWithdraw:** Emits when tokens are withdrawn from the contract to a specified destination.
  - Parameters: `destination`, `amount`

## Demo

Explore the demo folder to see practical examples of interacting with the TXMonitor Smart Contract and monitoring transactions using events.

---

For detailed instructions and examples, refer to the demo folder and the provided documentation. Happy monitoring with TXMonitor Smart Contract!
