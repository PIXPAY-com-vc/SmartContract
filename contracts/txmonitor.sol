// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./openzeppelin/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";


contract TXMonitor is Ownable, ReentrancyGuard {
   
    using SafeERC20 for IERC20;

    address public usdtTokenContractAddress;
    string public bussinessId;

    receive() external payable {
        // The contract can receive MATIC (ETH) transfers here
    }

    event Deposit(address senderWallet,address indexed receiverWallet, uint256 indexed amount,bytes message);
    event Withdraw(address senderWallet,address indexed receiverWallet, uint256 indexed amount,bytes message);
    event TokensWithdraw(address indexed destination,uint256 amount);

    constructor(address initialOwner, address _usdtTokenContractAddress, string memory _bussinessId)
    Ownable(initialOwner) {
        bussinessId = _bussinessId;
        usdtTokenContractAddress = _usdtTokenContractAddress;
    }

    function setUsdtTokenContractAddress(address _usdtTokenContractAddress) external onlyOwner {
        usdtTokenContractAddress = _usdtTokenContractAddress;
    }

    function transfer(address recipient, uint256 amount,uint256 txtype, bytes memory memo) external nonReentrant {
        require(amount > 0, "Amount must be greater than 0");
        require(recipient != address(0), "Invalid destination address");
        
        if(txtype == 0 ){
       
            // Transfer the amount to the destination address
            IERC20(usdtTokenContractAddress).transferFrom(msg.sender, recipient, amount);

            emit Deposit(msg.sender,recipient,amount,memo);

        } else {

            emit Withdraw(msg.sender,recipient,amount,memo);

        }
    }

    function withdrawToken(address _tokenAddress, uint256 _quantity) public onlyOwner {
    
        IERC20(_tokenAddress).transfer(msg.sender,_quantity);

        emit TokensWithdraw(msg.sender,_quantity);

    }

    function withdrawMatic() public onlyOwner {
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        require(success, "Withdrawal failed");
    }

}