import hashlib
import time
import json

class Transaction:
    """Represents a transaction in the blockchain."""
    def __init__(self, sender, receiver, amount):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount

    def __repr__(self):
        return f"Transaction({self.sender} -> {self.receiver}: {self.amount})"

    def to_dict(self):
        """Converts transaction to a dictionary for serialization."""
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount
        }

class MerkleTree:
    """Merkle Tree for storing transactions and calculating the Merkle Root."""
    def __init__(self, transactions):
        self.transactions = transactions
        self.root = self.build_tree([self.hash_data(str(tx)) for tx in transactions])

    @staticmethod
    def hash_data(data):
        """Hashes the input data using SHA-256."""
        return hashlib.sha256(data.encode()).hexdigest()

    def build_tree(self, leaves):
        """Recursively builds the tree and returns the Merkle root."""
        if len(leaves) == 1:
            return leaves[0]
        if len(leaves) % 2 == 1:
            leaves.append(leaves[-1])  # Duplicate last leaf if odd number of leaves
        parent_layer = [self.hash_data(leaves[i] + leaves[i + 1]) for i in range(0, len(leaves), 2)]
        return self.build_tree(parent_layer)

class Block:
    """Block structure for the blockchain."""
    def __init__(self, index, previous_hash, transactions, timestamp=None, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.timestamp = timestamp or int(time.time())
        self.nonce = nonce
        self.merkle_root = MerkleTree(transactions).root
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Calculates the SHA-256 hash of the block, including the Merkle root."""
        block_string = f"{self.index}{self.previous_hash}{self.merkle_root}{self.timestamp}{self.nonce}".encode()
        return hashlib.sha256(block_string).hexdigest()

class Blockchain:
    """Blockchain structure to manage blocks and transactions."""
    def __init__(self, difficulty=2, filename="blockchain.json"):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.filename = filename
        self.load_chain()

    def create_genesis_block(self):
        """Creates the genesis block of the blockchain."""
        return Block(0, "0", [], nonce=0)

    def get_latest_block(self):
        """Returns the latest block in the blockchain."""
        return self.chain[-1]

    def add_block(self, new_block):
        """Adds a new block to the blockchain after mining it."""
        new_block.previous_hash = self.get_latest_block().hash
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)
        self.save_chain()

    def save_chain(self):
        """Saves the blockchain to a JSON file."""
        try:
            with open(self.filename, "w") as f:
                json.dump([self.block_to_dict(block) for block in self.chain], f)
        except IOError as e:
            print(f"Error saving blockchain: {e}")

    def load_chain(self):
        """Loads the blockchain from a JSON file if it exists."""
        try:
            with open(self.filename, "r") as f:
                self.chain = [self.dict_to_block(block_dict) for block_dict in json.load(f)]
        except FileNotFoundError:
            print("Blockchain file not found. Starting with a new chain.")
        except json.JSONDecodeError:
            print("Error decoding blockchain file. Starting with a new chain.")

    def block_to_dict(self, block):
        """Converts a block to a dictionary for serialization."""
        return {
            "index": block.index,
            "previous_hash": block.previous_hash,
            "transactions": [tx.to_dict() for tx in block.transactions],
            "timestamp": block.timestamp,
            "nonce": block.nonce,
            "merkle_root": block.merkle_root,
            "hash": block.hash
        }

    def dict_to_block(self, block_dict):
        """Converts a dictionary to a Block object."""
        transactions = [Transaction(**tx) for tx in block_dict["transactions"]]
        block = Block(block_dict["index"], block_dict["previous_hash"], transactions,
                      block_dict["timestamp"], block_dict["nonce"])
        block.hash = block_dict["hash"]  # Set the hash after creation
        return block

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
            print(f"  Transactions: {block.transactions}")
            print(f"  Timestamp: {block.timestamp}")
            print(f"  Nonce: {block.nonce}\n")
