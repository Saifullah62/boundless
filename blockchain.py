import hashlib
import time

# Block header structure equivalent in Python
class Block:
    def __init__(self, index, previous_hash, data, timestamp=None, nonce=0):
        """Initialize a new block with the given parameters."""
        self.index = index
        self.previous_hash = previous_hash
        self.data = data
        self.timestamp = timestamp or int(time.time())
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Calculate the SHA-256 hash of the block."""
        block_string = f"{self.index}{self.previous_hash}{self.data}{self.timestamp}{self.nonce}".encode()
        return hashlib.sha256(block_string).hexdigest()

    def mine_block(self, difficulty):
        """Mine the block by finding a hash that meets the difficulty criteria."""
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()

# Blockchain structure
class Blockchain:
    def __init__(self, difficulty=2):
        """Initialize the blockchain with a genesis block and a specified difficulty."""
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty

    def create_genesis_block(self):
        """Create the first block in the blockchain, known as the genesis block."""
        return Block(0, "0", "Genesis Block")

    def get_latest_block(self):
        """Return the latest block in the blockchain."""
        return self.chain[-1]

    def add_block(self, new_block):
        """Add a new block to the blockchain after mining it."""
        new_block.previous_hash = self.get_latest_block().hash
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

    def is_chain_valid(self):
        """Check the validity of the blockchain by verifying hashes and previous hashes."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if current_block.hash != current_block.calculate_hash():
                print(f"Invalid block at index {i}: hash mismatch.")
                return False
            if current_block.previous_hash != previous_block.hash:
                print(f"Invalid block at index {i}: previous hash mismatch.")
                return False
        return True

    def print_chain(self):
        """Print the details of each block in the blockchain."""
        for block in self.chain:
            print(f"Block {block.index}:")
            print(f"  Hash: {block.hash}")
            print(f"  Previous Hash: {block.previous_hash}")
            print(f"  Data: {block.data}")
            print(f"  Timestamp: {block.timestamp}")
            print(f"  Nonce: {block.nonce}\n")
