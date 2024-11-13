import json
from blockchain import Block, Blockchain

def test_blockchain():
    print("Creating a blockchain with difficulty 2 for testing...")
    blockchain = Blockchain(difficulty=2)
    
    print("Mining block 1...")
    blockchain.add_block(Block(1, blockchain.get_latest_block().hash, "Data for Block 1"))
    
    print("Mining block 2...")
    blockchain.add_block(Block(2, blockchain.get_latest_block().hash, "Data for Block 2"))
    
    print("Mining block 3...")
    blockchain.add_block(Block(3, blockchain.get_latest_block().hash, "Data for Block 3"))

    print("\nBlockchain verification:")
    is_valid = blockchain.is_chain_valid()
    print(f"Blockchain valid: {is_valid}")
    
    # Displaying the blockchain
    for block in blockchain.chain:
        print(json.dumps({
            "Index": block.index,
            "Timestamp": block.timestamp,
            "Data": block.data,
            "Nonce": block.nonce,
            "Hash": block.hash,
            "Previous Hash": block.previous_hash
        }, indent=4))

if __name__ == "__main__":
    test_blockchain()
