const ethers = require('ethers');
const fs = require('fs');
const monitor_ABIJSON = require('./monitor.json');
const { format } = require('date-fns');
const { EthCrypto } = require('eth-crypto');

// Configuration

// Public WebSocket RPC --  can use your own RPC for more performance and less rate limit
const websocketRPC = "wss://polygon.api.onfinality.io/public-ws";

const currentTimeFormatted = format(new Date(), 'yyyy-MM-dd HH:mm:ss');

const MONITOR_CONTRACT_ADDRESS = "0x.."; // Your SmartContract for deployed smart contract Monitor
const hotWallet = "0x..." // Platform HotWallet Address
const privateKey = "privateKey";  // Private Key of the public key provided

// End Configuration

// Set the Provider
const provider = new ethers.providers.WebSocketProvider(websocketRPC);

// Set Contract for use
const monitorContractChecker = new ethers.Contract(monitor_CONTRACT_ADDRESS, monitor_ABIJSON, provider);


// tracking Deposit Event
monitorContractChecker.on("Deposit", async (from, to, amount, memo, event) => {

    /* MEMO Object we send
            {
              timestamp: Date,
              businessID: string,
              amountBRL: string,
              exchangeRate: string,
              fee: string,
              payername: string,
              cpf: string,
              mobile: string,
              email: string,
              e2eID: string,
              geolocation: string
            };

    */
    try {

        console.log("Event received:");
        console.log("From:", from);
        console.log("To:", to);
        console.log("memo:", memo);
        console.log("TxHash: ", event.transactionHash);
        
        const utf8String = Buffer.from(memo.slice(2), 'hex').toString('utf8');
        console.log("transformed memo hex > ", JSON.parse(utf8String));

        // Decrypt the memo message
        const decryptedData = await EthCrypto.decryptWithPrivateKey(
            privateKey,   // Private Key of the public key provided
            JSON.parse(utf8String)
        );

        const decryptedDataOBJ = JSON.parse(decryptedData);

        console.log('Decrypted Message:', decryptedDataOBJ);
        console.log('Bussiness ID: ', decryptedDataOBJ.bussinessID);
        console.log('Amount: ', decryptedDataOBJ.amountBRL);
        console.log('Exchange Rate: ', decryptedDataOBJ.exchangeRate);
        console.log('End2End: ', decryptedDataOBJ.e2eID);

    } catch (error) {
        console.error('Error processing event:', error);
    }
});

// tracking Withdraw Event
monitorContractChecker.on("Withdraw", async (from, to, amount, memo, event) => {
    /* MEMO Object we send
         {
           timestamp: Date,
           businessID: string,
           amountBRL: string,
           exchangeRate: string,
           fee: string,
           payername: string,
           cpf: string,
           mobile: string,
           email: string,
           e2eID: string,
           geolocation: string
         };

 */

    try {
        console.log("Event received:");
        console.log("From:", from);
        console.log("To:", to);
        console.log("memo:", memo);
        console.log("TxHash: ", event.transactionHash);

        const utf8String = Buffer.from(memo.slice(2), 'hex').toString('utf8');
        console.log("transformed memo hex > ", JSON.parse(utf8String));

        // Decrypt the memo message
        const decryptedData = await EthCrypto.decryptWithPrivateKey(
            privateKey,   // Private Key of the public key provided
            JSON.parse(utf8String)
        );

        const decryptedDataOBJ = JSON.parse(decryptedData);

        console.log('Decrypted Message:', decryptedDataOBJ);
        console.log('Bussiness ID: ', decryptedDataOBJ.bussinessId);
        console.log('Amount: ', decryptedDataOBJ.amount);
        console.log('Exchange Rate: ', decryptedDataOBJ.exchangeRate);
        console.log('End2End: ', decryptedDataOBJ.e2e);

    } catch (error) {
        console.error('Error processing event:', error);
    }
});