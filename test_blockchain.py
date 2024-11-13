import os
import json
from blockchain import Block, Blockchain, Transaction, MerkleTree

def test_transactions():
    """Test adding transactions to a block."""
    print("Testing Transactions...")
    tx1 = Transaction("Alice", "Bob", 50)
    tx2 = Transaction("Bob", "Charlie", 25)
    block = Block(1, "0" * 64, [tx1, tx2])
    assert len(block.transactions) == 2, "Block should contain 2 transactions"
    print("Transaction Test Passed")

def test_merkle_tree():
    """Test Merkle Tree generation and root calculation."""
    print("Testing Merkle Tree...")
    transactions = [Transaction("Alice", "Bob", 50), Transaction("Bob", "Charlie", 25)]
    merkle_tree = MerkleTree(transactions)
    root_hash = merkle_tree.root
    assert root_hash is not None, "Merkle Root should not be None"
    print("Merkle Tree Test Passed")

def test_persistence():
    """Test saving and loading the blockchain to/from a file."""
    print("Testing Persistence...")
    filename = "test_blockchain.json"
    blockchain = Blockchain(filename=filename)
    
    # Add some blocks with transactions
    tx1 = Transaction("Alice", "Bob", 50)
    blockchain.add_block(Block(1, blockchain.get_latest_block().hash, [tx1]))

    tx2 = Transaction("Bob", "Charlie", 25)
    blockchain.add_block(Block(2, blockchain.get_latest_block().hash, [tx2]))
    
    # Save chain to file
    blockchain.save_chain()
    assert os.path.exists(filename), "Blockchain file should exist after saving"
    
    # Load chain and verify data integrity
    new_blockchain = Blockchain(filename=filename)
    new_blockchain.load_chain()
    assert len(new_blockchain.chain) == len(blockchain.chain), "Loaded chain should match saved chain length"
    
    # Clean up
    os.remove(filename)
    print("Persistence Test Passed")

def test_blockchain_integrity():
    """Test the integrity of the blockchain with added blocks and transactions."""
    print("Testing Blockchain Integrity...")
    blockchain = Blockchain()
    
    # Genesis block check
    assert blockchain.is_chain_valid(), "Initial chain with genesis block should be valid"
    
    # Add new blocks
    tx1 = Transaction("Alice", "Bob", 50)
    tx2 = Transaction("Bob", "Charlie", 25)
    blockchain.add_block(Block(1, blockchain.get_latest_block().hash, [tx1, tx2]))
    
    tx3 = Transaction("Charlie", "Dave", 10)
    blockchain.add_block(Block(2, blockchain.get_latest_block().hash, [tx3]))
    
    # Verify chain integrity
    assert blockchain.is_chain_valid(), "Blockchain should be valid after adding blocks"
    
    # Tamper with the blockchain and check integrity
    blockchain.chain[1].transactions[0] = Transaction("Alice", "Mallory", 100)  # Changing a transaction
    assert not blockchain.is_chain_valid(), "Blockchain should be invalid after tampering with a block"
    
    print("Blockchain Integrity Test Passed")

def test_block_mining():
    """Test that mining a block produces a hash with the required difficulty."""
    print("Testing Block Mining...")
    difficulty = 2  # Adjust difficulty as needed for testing
    tx1 = Transaction("Alice", "Bob", 50)
    block = Block(1, "0" * 64, [tx1])
    block.mine_block(difficulty)
    assert block.hash.startswith("0" * difficulty), f"Block hash should start with {'0' * difficulty}"
    print("Block Mining Test Passed")

# Run all tests
if __name__ == "__main__":
    print("Running Blockchain Tests...")
    test_transactions()
    test_merkle_tree()
    test_persistence()
    test_blockchain_integrity()
    test_block_mining()
    print("All Tests Passed!")

