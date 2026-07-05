// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Clean {
    address public owner;
    uint256 public value;

    event ValueChanged(uint256 newValue);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function setValue(uint256 _value) external onlyOwner {
        value = _value;
        emit ValueChanged(_value);
    }
}
