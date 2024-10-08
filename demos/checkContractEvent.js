const ethers = require('ethers');
const fs = require('fs');
const monitor_ABIJSON = require('./monitor.json');
const { format } = require('date-fns');
const { EthCrypto } = require('eth-crypto');

// Configuration

// Public WebSocket RPC --  can use your own RPC for more performance and less rate limit
const websocketRPC = "wss://polygon.api.onfinality.io/public-ws";

const currentTimeFormatted = format(new Date(), 'yyyy-MM-dd HH:mm:ss');

const MONITOR_CONTRACT_ADDRESS = "0x...."; // Your SmartContract for deployed smart contract Monitor
const hotWallet = "0x..." // Platform HotWallet Address
const privateKey = "";  // Private Key of the public key provided

// End Configuration

// Set the Provider
const provider = new ethers.providers.WebSocketProvider(websocketRPC);

// Set Contract for use
const monitorContractChecker = new ethers.Contract(MONITOR_CONTRACT_ADDRESS, monitor_ABIJSON, provider);


// tracking Deposit Event
monitorContractChecker.on("Deposit", async (from, to, amount, msgId, message, encrypt, event) => {

    /* MEMO Object we send
    {
        datetime: string,
        amountBRL: string,
        amountUSDT: string,
        destination: string,
        e2e: string
    };

    */
    try {

        console.log("Event received:");
        console.log("From:", from);
        console.log("To:", to);
        console.log("memo:", message);
        console.log("msgId:", msgId);
        console.log("TxHash: ", event.transactionHash);

        let decryptedData;

        if (encrypt === true) {
            const utf8String = Buffer.from(memo.slice(2), 'hex').toString('utf8');

            // Decrypt the memo message
            decryptedData = await EthCrypto.decryptWithPrivateKey(
                privateKey,   // Private Key of the public key provided
                JSON.parse(utf8String)
            );

        } else {

            const utf8String = Buffer.from(memo.slice(2), 'hex').toString('utf8');

            decryptedData = JSON.parse(utf8String)

        }

        const decryptedDataOBJ = encrypt ? JSON.parse(decryptedData) : decryptedData;

        console.log('Decrypted Message:', decryptedDataOBJ);
        console.log('Date: ', decryptedDataOBJ.datetime);
        console.log('AmountBRL: ', decryptedDataOBJ.amountBRL);
        console.log('AmountUSDT: ', decryptedDataOBJ.amountUSDT);
        console.log('End2End: ', decryptedDataOBJ.e2e);

    } catch (error) {
        console.error('Error processing event:', error);
    }
});

// tracking Withdraw Event
monitorContractChecker.on("Withdraw", async (from, to, amount, message, encrypt, event) => {

    /* MEMO Object we send
        {
            datetime: string,
            amountBRL: string,
            amountUSDT: string,
            destination: string,
            e2e: string
        };
    */

    try {
        console.log("Event received:");
        console.log("From:", from);
        console.log("To:", to);
        console.log("memo:", message);
        console.log("TxHash: ", event.transactionHash);

        let decryptedData;

        if (encrypt === true) {
            const utf8String = Buffer.from(memo.slice(2), 'hex').toString('utf8');

            // Decrypt the memo message
            decryptedData = await EthCrypto.decryptWithPrivateKey(
                privateKey,   // Private Key of the public key provided
                JSON.parse(utf8String)
            );

        } else {

            const utf8String = Buffer.from(memo.slice(2), 'hex').toString('utf8');

            decryptedData = JSON.parse(utf8String)

        }

        const decryptedDataOBJ = encrypt ? JSON.parse(decryptedData) : decryptedData;

        console.log('Decrypted Message:', decryptedDataOBJ);
        console.log('Date: ', decryptedDataOBJ.datetime);
        console.log('AmountBRL: ', decryptedDataOBJ.amountBRL);
        console.log('AmountUSDT: ', decryptedDataOBJ.amountUSDT);
        console.log('End2End: ', decryptedDataOBJ.e2e);

    } catch (error) {
        console.error('Error processing event:', error);
    }
});