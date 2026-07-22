// FIXTURE: Solidity vulnerabilities. Each PLANT must be caught by static/solidity.
// SPDX-License-Identifier: MIT

// PLANT: floating-pragma (low)
pragma solidity ^0.8.0;

contract Vault {
    address owner;
    mapping(address => uint256) balances;

    // PLANT: unprotected-selfmint-or-transfer (mint has no access control)
    function mint(address to, uint256 amount) public {
        balances[to] += amount;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        // PLANT: unchecked-low-level-call (medium) + reentrancy shape
        (bool ok, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }

    // PLANT: tx-origin-auth (high)
    function adminOnly() public view {
        require(tx.origin == owner, "not owner");
    }

    // PLANT: blockhash-randomness (high)
    function random() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty)));
    }

    // PLANT: selfdestruct (high)
    function kill() public {
        selfdestruct(payable(owner));
    }
}
