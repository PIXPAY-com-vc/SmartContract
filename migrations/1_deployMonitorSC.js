const { BigNumber } = require("@ethersproject/bignumber");
const Token = artifacts.require("TXMonitor");

const logTx = (tx) => {
    console.dir(tx, {depth: 3});
}

// let block = await web3.eth.getBlock("latest")
module.exports = async function(deployer, network, accounts) {

    const currentAccount = accounts[0];

    const usdtContractAddress = "0xc2132D05D31c914a87C6611C10748AEb04B58e8F";   // Default Polygon USDT address
    const businessId = ""; // choose your bussiness ID EX: abc123

    /**
     * Deploy Token
     */
    deployer.deploy(Token, currentAccount, usdtContractAddress, businessId).then((tx) => {      
     logTx(tx);
    })
};