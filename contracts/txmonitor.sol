// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./openzeppelin/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";


contract TXMonitor is Ownable, ReentrancyGuard {
   
    using SafeERC20 for IERC20;

    address public usdtTokenContractAddress;
    address public vrlTokenContractAddress;
    string public businessId;

    receive() external payable {
        // The contract can receive MATIC (ETH) transfers here
    }

    event Deposit(address senderWallet,address indexed receiverWallet, uint256 indexed amount, string msgId, bytes message, bool encrypt, string token);
    event Withdraw(address senderWallet,address indexed receiverWallet, uint256 indexed amount, string msgId, bytes message, bool encrypt, string token);
    event TokensWithdraw(address indexed destination,uint256 amount);

    constructor(address initialOwner, address _usdtTokenContractAddress, address _vrlTokenContractAddress, string memory _businessId)
    Ownable() {
        businessId = _businessId;
        usdtTokenContractAddress = _usdtTokenContractAddress;
        vrlTokenContractAddress = _vrlTokenContractAddress;
    }

    function setUsdtTokenContractAddress(address _usdtTokenContractAddress) external onlyOwner {
        usdtTokenContractAddress = _usdtTokenContractAddress;
    }


    function setVrlTokenContractAddress(address _vrlTokenContractAddress) external onlyOwner {
        vrlTokenContractAddress = _vrlTokenContractAddress;
    }

    function transfer(address recipient, uint256 amount, uint256 txtype, string memory msgId, bytes memory memo, bool encrypt, string memory token) external nonReentrant {
        require(amount > 0, "Amount must be greater than 0");
        require(recipient != address(0), "Invalid destination address");
        
        bytes32 tokenHash = keccak256(abi.encodePacked(token));

        if (tokenHash == keccak256(abi.encodePacked("USDT"))) {
            IERC20(usdtTokenContractAddress).transferFrom(msg.sender, recipient, amount);
        } else if (tokenHash == keccak256(abi.encodePacked("VRL"))) {
            IERC20(vrlTokenContractAddress).transferFrom(msg.sender, recipient, amount);
        } else {
            revert("Unsupported token");
        }

        if(txtype == 0 ){

            emit Deposit(msg.sender, recipient, amount, msgId, memo, encrypt, token);

        } else {

            emit Withdraw(msg.sender, recipient, amount, msgId, memo, encrypt, token);

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
