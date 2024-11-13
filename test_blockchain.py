import json
from blockchain import Block, Blockchain


def create_and_mine_block(blockchain, index, data):
    """
    Creates and mines a new block in the blockchain.
    
    Args:
        blockchain (Blockchain): The blockchain instance to which the block will be added.
        index (int): The index of the block to be created.
        data (str): The data to be stored in the block.
    """
    print(f"Mining block {index}...")
    latest_block = blockchain.get_latest_block()
    blockchain.add_block(Block(index, latest_block.hash, data))


def display_blockchain(chain):
    """
    Displays the entire blockchain in a readable JSON format.
    
    Args:
        chain (list): The list of blocks in the blockchain.
    """
    print("\nDisplaying the blockchain:")
    blocks_data = [
        {
            "Index": block.index,
            "Timestamp": block.timestamp,
            "Data": block.data,
            "Nonce": block.nonce,
            "Hash": block.hash,
            "Previous Hash": block.previous_hash
        }
        for block in chain
    ]
    print(json.dumps(blocks_data, indent=4))


def test_blockchain():
    """
    Tests the blockchain by creating a new instance, mining blocks, and verifying the chain.
    """
    print("Creating a blockchain with difficulty 2 for testing...")
    blockchain = Blockchain(difficulty=2)
    
    # Mine blocks
    for i in range(1, 4):
        create_and_mine_block(blockchain, i, f"Data for Block {i}")

    # Verify blockchain
    print("\nBlockchain verification:")
    is_valid = blockchain.is_chain_valid()
    print(f"Blockchain valid: {is_valid}")
    
    # Display the blockchain
    display_blockchain(blockchain.chain)


if __name__ == "__main__":
    try:
        test_blockchain()
    except Exception as e:
        print(f"Error in blockchain test: {e}")
