class Blockchain:
    """Represents the blockchain itself, managing the chain of blocks."""
    def __init__(self, difficulty=2, filename="blockchain.json"):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.filename = filename
        # Mock methods for testing
        self.block_times = []  # Track mining times for blocks
        self.peers = set()  # Set of known peer addresses (e.g., 'IP:PORT')
        self.mempool = []  # Priority queue (min-heap) for unconfirmed transactions

    def create_genesis_block(self):
        return "Genesis Block"  # Placeholder for the genesis block

if __name__ == "__main__":
    try:
        blockchain = Blockchain(difficulty=2)
        print("Blockchain initialized with difficulty:", blockchain.difficulty)
    except TypeError as e:
        print("Error:", e)
