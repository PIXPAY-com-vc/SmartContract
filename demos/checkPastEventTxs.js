const ethers = require('ethers');
const fs = require('fs');
const monitor_ABIJSON = require('./monitor.json');
const { format } = require('date-fns');
const EthCrypto = require('eth-crypto');

// Configuration

// Public WebSocket RPC --  can use your own RPC for more performance and less rate limit
const websocketRPC = "wss://polygon-mainnet.g.alchemy.com/v2/hQVqFUlQfk1ELZkRz3zXlmjJGGx_Pshy";

const currentTimeFormatted = format(new Date(), 'yyyy-MM-dd HH:mm:ss');

const MONITOR_CONTRACT_ADDRESS = "0x707E1Af57f99eF4c10Fd8795adfa6dB78FEd3cE2"; // Your SmartContract for Splitter provided by Digital Horizon
const smpWallet = "" // SmartPay verified Address
const hotWallet = "0xCB6e1468f05853ecb603A1988cdC8a136650298f" // Platform HotWallet Address
const privateKey = ""; // Your private key EX:

// End Configuration

// Set the Provider
const provider = new ethers.providers.WebSocketProvider(websocketRPC);

// Set Contract for use
const monitorContractChecker = new ethers.Contract(MONITOR_CONTRACT_ADDRESS, monitor_ABIJSON, provider);

async function decryptMemo(memoHex) {
    try {
        const utf8String = Buffer.from(memoHex.slice(2), 'hex').toString('utf8');
        const decryptedData = await EthCrypto.decryptWithPrivateKey(privateKey, JSON.parse(utf8String));
        return JSON.parse(decryptedData);
    } catch (error) {
        console.error("Error decrypting memo:", error);
        return null;
    }
}

// For a more advanced Database Onchain use Subgraphs

async function getPastEvents() {  // can use a parameter to filter here, a txhash or wallet etc
    try {
        // Define the event filter for the Deposit event
        const depositFilter = monitorContractChecker.filters.Deposit(); // name of event here Aka : Deposit or Withdraw  Disclaimer: Payment on the DEMO contract

        // Define the event filter for the Withdraw event
        const withdrawFilter = monitorContractChecker.filters.Withdraw();

        // Get first past events using the event filter
        // let pastEvents = await splitterContractChecker.queryFilter(depositFilter);

        // Or you can get fromBlock to Block using
        // Specify the block range (fromBlock and toBlock) to get a range of events and get a list and possibly filter by transactionHash
        const fromBlock = 1000; // Replace with your desired starting block number
        const toBlock = 'latest'; // Use 'latest' for the latest block, or specify a block number

       let pastEvents = await monitorContractChecker.queryFilter(depositFilter,fromBlock,toBlock);

        // Process each past event
        for (const event of pastEvents) {

            const { message: memoHex, receiverWallet: to , senderWallet: from, amount: value } = event.args;
            
            console.log("EVENT TX HASH ", event.transactionHash);
            console.log("EVENT RECEIVER WALLET : ", to);
            console.log("EVENT SENDER WALLET : ", from);
            console.log("EVENT AMOUNT :", ethers.utils.formatUnits(value, 6));

            // You can filter by event argument here to decrypt specific info etc
            // if(event.transactionHash === "0x") or if(receiverWallet === "0x...") etc
            const decryptedMemo = await decryptMemo(memoHex);

            if (decryptedMemo) {
                console.log("Decrypted Memo:", decryptedMemo);
            } else {
                console.log("Failed to decrypt memo.");
            }
        }
    } catch (error) {
        console.error("Error fetching past events:", error);
    }
}

// Call the function to get past events
getPastEvents();

// Call the function to get past events for a specific transaction hash
const txHash = "0xf74931971ab9c36bdb7acee673b6eea24af9bdb0a17d446566de1b77fad7d529";
// getPastEvents(txHash);