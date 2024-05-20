// SPDX-License-Identifier: MIT

pragma solidity >=0.6.2 <=0.8.20;

interface IERC20 {
    function transfer(address recipient, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}
