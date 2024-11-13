import hashlib
import time

# Block header structure equivalent in Python
class Block:
    def __init__(self, index, previous_hash, data, timestamp=None, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.data = data
        self.timestamp = timestamp or int(time.time())
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.previous_hash}{self.data}{self.timestamp}{self.nonce}".encode()
        return hashlib.sha256(block_string).hexdigest()

    def mine_block(self, difficulty):
        # Target is a string of leading zeroes based on the difficulty level
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()

# Blockchain structure
class Blockchain:
    def __init__(self, difficulty=2):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty

    def create_genesis_block(self):
        return Block(0, "0", "Genesis Block")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, new_block):
        new_block.previous_hash = self.get_latest_block().hash
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            # Check if current block's hash is correctly calculated
            if current_block.hash != current_block.calculate_hash():
                return False
            # Check if current block's previous_hash matches the previous block's hash
            if current_block.previous_hash != previous_block.hash:
                return False
        return True
