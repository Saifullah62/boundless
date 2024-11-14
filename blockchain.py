# Standard library imports
import hashlib
import json
import os
import time
import logging
import re
import socket
import ssl
import secrets
from collections import defaultdict
from datetime import datetime, timedelta
import heapq
import threading

# Third-party imports
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature
from dotenv import load_dotenv

# Network constants for peer-to-peer communication
PORT = 5000
BUFFER_SIZE = 4096
RATE_LIMIT_WINDOW = timedelta(seconds=10)  # Rate limiting window
MAX_REQUESTS_PER_WINDOW = 5

# Setup logging
logging.basicConfig(
    filename='blockchain.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# Load environment variables
load_dotenv()

# Access token for peer authentication
ACCESS_TOKEN = os.getenv("ACCESS_TOKEN", secrets.token_hex(16))

# Rate limiting dictionary
rate_limit_tracker = defaultdict(lambda: defaultdict(list))

class Transaction:
    """Represents a transaction in the blockchain."""
    def __init__(self, sender, receiver, amount, private_key=None):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.signature = None
        if private_key:
            self.sign_transaction(private_key)

    def __repr__(self):
        return f"Transaction({self.sender} -> {self.receiver}: {self.amount})"

    def to_dict(self):
        """Converts the transaction to a dictionary representation."""
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "signature": self.signature.hex() if self.signature else None
        }

    def sign_transaction(self, private_key):
        """Signs the transaction using the sender's private key."""
        transaction_data = f"{self.sender}{self.receiver}{self.amount}".encode()
        self.signature = private_key.sign(
            transaction_data,
            ec.ECDSA(hashes.SHA256())
        )

    def verify_signature(self, public_key):
        """Verifies the transaction signature."""
        transaction_data = f"{self.sender}{self.receiver}{self.amount}".encode()
        try:
            public_key.verify(
                self.signature,
                transaction_data,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            logging.warning(f"Invalid signature for transaction from {self.sender} to {self.receiver}.")
            return False

class MerkleTree:
    """Constructs a Merkle Tree from a list of transactions."""
    def __init__(self, transactions):
        self.transactions = transactions
        self.root = self.build_tree([self.hash_data(str(tx)) for tx in transactions])

    @staticmethod
    def hash_data(data):
        """Hashes the given data using SHA-512."""
        return hashlib.sha512(data.encode()).digest()  # Store hash as a byte array, not a hex string

    def build_tree(self, leaves):
        """Builds the Merkle Tree iteratively from the leaves."""
        while len(leaves) > 1:
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1])  # Use a reference instead of a duplicate
            parent_layer = [
                self.hash_data(leaves[i] + leaves[i + 1]) for i in range(0, len(leaves), 2)
            ]
            leaves = parent_layer
        return leaves[0] if leaves else None

class Block:
    """Represents a block in the blockchain."""
    def __init__(self, index, previous_hash, transactions, timestamp=None, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.timestamp = timestamp or int(time.time())
        self.nonce = nonce
        self.merkle_root = MerkleTree(transactions).root
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Calculates the SHA-512 hash of the block."""
        block_string = f"{self.index}{self.previous_hash}{self.merkle_root}{self.timestamp}{self.nonce}".encode()
        return hashlib.sha512(block_string).hexdigest()

    def mine_block(self, difficulty):
        """Mines the block by finding a hash that meets the difficulty target."""
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()

class Blockchain:
    """Represents the blockchain itself, managing the chain of blocks."""
    def __init__(self, difficulty=2, filename="blockchain.json"):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.filename = filename
        self.load_chain()
        self.block_times = []  # Track mining times for blocks
        self.peers = set()  # Set of known peer addresses (e.g., 'IP:PORT')
        self.mempool = []  # Priority queue (min-heap) for unconfirmed transactions

        # Start peer discovery in a separate thread
        discovery_thread = threading.Thread(target=self.peer_discovery)
        discovery_thread.daemon = True
        discovery_thread.start()

    def create_genesis_block(self):
        """Creates the first block in the blockchain."""
        return Block(0, "0", [], nonce=0)

    def get_latest_block(self):
        """Returns the latest block in the blockchain."""
        return self.chain[-1]

    def add_transaction(self, transaction, fee=0):
        """Adds a transaction to the mempool with an optional fee for prioritization."""
        # Validate transaction signature
        if not transaction.verify_signature(self.get_public_key(transaction.sender)):
            logging.warning(f"Transaction {transaction} has an invalid signature and was not added to the mempool.")
            return False

        # Use fee and timestamp to prioritize transactions in the mempool
        priority = (-fee, time.time())  # Negative fee for max-heap behavior using min-heap
        heapq.heappush(self.mempool, (priority, transaction))
        logging.info(f"Transaction {transaction} added to mempool with fee {fee}.")
        return True

    def select_transactions_for_block(self, max_transactions=10):
        """Selects transactions from the mempool for the next block, prioritizing by fee and timestamp."""
        selected_transactions = []
        while self.mempool and len(selected_transactions) < max_transactions:
            _, transaction = heapq.heappop(self.mempool)
            selected_transactions.append(transaction)
        return selected_transactions

    def add_block(self, new_block):
        """Adds a new block to the blockchain after mining it."""
        # Select high-priority transactions for the new block
        new_block.transactions = self.select_transactions_for_block()

        new_block.previous_hash = self.get_latest_block().hash
        start_time = time.time()
        new_block.mine_block(self.difficulty)
        end_time = time.time()

        self.block_times.append(end_time - start_time)
        logging.info(f"Block {new_block.index} mined in {end_time - start_time:.2f} seconds with difficulty {self.difficulty}")

        self.adjust_difficulty()
        self.chain.append(new_block)
        self.save_chain()

    def adjust_difficulty(self):
        """Adjusts the mining difficulty based on the average block time."""
        if len(self.block_times) >= 10:
            avg_mining_duration = sum(self.block_times[-10:]) / 10
            target_duration = 180  # Target block time in seconds
            lower_bound = 150  # Lower acceptable bound
            upper_bound = 210  # Upper acceptable bound

            if avg_mining_duration < lower_bound:
                self.difficulty = min(self.difficulty + 2, self.difficulty * 2)  # Cap the increase for smoother transition
            elif avg_mining_duration > upper_bound:
                self.difficulty = max(1, max(self.difficulty - 2, int(self.difficulty / 2)))  # Cap the decrease
            else:
                # Proportional adjustment if within 10% difference
                adjustment_factor = avg_mining_duration / target_duration
                if adjustment_factor < 0.9:
                    self.difficulty = int(self.difficulty * adjustment_factor)
                elif adjustment_factor > 1.1:
                    self.difficulty = max(1, int(self.difficulty / adjustment_factor))

    def save_chain(self):
        """Saves the blockchain to a JSON file."""
        try:
            with open(self.filename, "w") as f:
                json.dump([self.block_to_dict(block) for block in self.chain], f, indent=4)
            logging.info("Blockchain saved successfully.")
        except (IOError, Exception) as e:
            logging.error(f"Failed to save blockchain to file: {e}")

    def load_chain(self):
        """Loads the blockchain from a JSON file."""
        try:
            with open(self.filename, "r") as f:
                data = json.load(f)
                self.chain = [self.dict_to_block(block_data) for block_data in data]
            logging.info("Blockchain loaded successfully.")
        except FileNotFoundError:
            logging.warning(f"No blockchain file found at {self.filename}. Starting with the genesis block.")
        except json.JSONDecodeError as e:
            logging.error(f"Failed to decode JSON while loading blockchain: {e}")
        except IOError as e:
            logging.error(f"Failed to load blockchain from file: {e}")
        except Exception as e:
            logging.error(f"Unexpected error while loading blockchain: {e}")

    @staticmethod
    def block_to_dict(block):
        """Converts a block to a dictionary representation."""
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
        """Converts a dictionary representation back to a block."""
        transactions = [Transaction(**tx) for tx in block_dict["transactions"]]
        block = Block(block_dict["index"], block_dict["previous_hash"], transactions,
                      block_dict["timestamp"], block_dict["nonce"])
        block.hash = block_dict["hash"]
        return block

    def is_chain_valid(self):
        """Validates the blockchain by checking hashes, previous hashes, and transaction signatures."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if current_block.hash != current_block.calculate_hash():
                logging.error(f"Invalid block at index {i}: hash mismatch.")
                return False
            if current_block.previous_hash != previous_block.hash:
                logging.error(f"Invalid block at index {i}: previous hash mismatch.")
                return False
            # Verify all transactions
            for transaction in current_block.transactions:
                if not transaction.verify_signature(self.get_public_key(transaction.sender)):
                    logging.error(f"Invalid signature for transaction {transaction}")
                    return False
        return True

    def get_public_key(self, public_key_pem):
        """Deserializes a public key from PEM format."""
        try:
            return serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        except ValueError as e:
            logging.error(f"Failed to load public key: {e}")
            raise

    def connect_to_blockchain(self, host):
        """Connect to a peer's blockchain and sync if their chain is longer."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, PORT)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as s:
                    s.sendall(f"REQUEST_BLOCKCHAIN|{ACCESS_TOKEN}".encode())
                    data = b""
                    while True:
                        part = s.recv(BUFFER_SIZE)
                        if not part:
                            break
                        data += part

                    received_chain = json.loads(data.decode())
                    received_chain_objects = [self.dict_to_block(block) for block in received_chain]

                    if self.is_valid_chain(received_chain_objects) and len(received_chain_objects) > len(self.chain):
                        logging.info("Replacing current blockchain with the received chain.")
                        self.chain = received_chain_objects
                        self.save_chain()
                    else:
                        logging.info("Received blockchain is not valid or shorter. No update performed.")

        except socket.error as e:
            logging.error(f"Failed to connect to {host}:{PORT} - {e}")
        except json.JSONDecodeError as e:
            logging.error(f"Failed to decode blockchain JSON data from {host}:{PORT} - {e}")
        except Exception as e:
            logging.error(f"Unexpected error while connecting to blockchain: {e}")

    def is_valid_chain(self, chain):
        """Check if a given chain is valid by verifying hashes, previous hashes, and signatures."""
        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i - 1]
            if current_block.hash != current_block.calculate_hash():
                return False
            if current_block.previous_hash != previous_block.hash:
                return False
            for transaction in current_block.transactions:
                if not transaction.verify_signature(self.get_public_key(transaction.sender)):
                    return False
        return True

class MultiSigTransaction:
    """Represents a multi-signature transaction in the blockchain."""
    def __init__(self, sender, receiver, amount, required_signatures=2):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.signatures = []
        self.required_signatures = required_signatures  # e.g., 2 out of 3 signatures required

    def to_dict(self):
        """Converts the transaction to a dictionary representation."""
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "signatures": [sig.hex() for sig in self.signatures]
        }

    def sign_transaction(self, private_key):
        """Adds a signature from a private key."""
        transaction_data = f"{self.sender}{self.receiver}{self.amount}".encode()
        signature = private_key.sign(transaction_data, ec.ECDSA(hashes.SHA256()))
        self.signatures.append(signature)

    def verify_signatures(self, public_keys):
        """Verifies that the transaction has the required number of valid signatures."""
        if len(self.signatures) < self.required_signatures:
            return False
        
        valid_signatures = 0
        transaction_data = f"{self.sender}{self.receiver}{self.amount}".encode()

        for public_key, signature in zip(public_keys, self.signatures):
            try:
                public_key.verify(signature, transaction_data, ec.ECDSA(hashes.SHA256()))
                valid_signatures += 1
            except InvalidSignature:
                continue

            # Check if enough valid signatures are met
            if valid_signatures >= self.required_signatures:
                return True

        return False

# Server function for peer-to-peer communication

def start_server(blockchain):
    """Starts a server to listen for blockchain requests from peers."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("0.0.0.0", PORT))
        server.listen(5)
        with context.wrap_socket(server, server_side=True) as tls_server:
            logging.info(f"Blockchain server listening on port {PORT} with TLS")

            while True:
                try:
                    client_socket, address = tls_server.accept()
                    with client_socket:
                        if not rate_limit_check(address[0], "NEW_TRANSACTION"):
                            logging.warning(f"Rate limit exceeded for {address[0]}")
                            client_socket.sendall(b"RATE_LIMIT_EXCEEDED")
                            continue

                        request = client_socket.recv(BUFFER_SIZE).decode()
                        request_parts = request.split("|")

                        # Handle different requests
                        if request_parts[0] == "REQUEST_BLOCKCHAIN" and request_parts[1] == ACCESS_TOKEN:
                            blockchain_data = json.dumps([blockchain.block_to_dict(block) for block in blockchain.chain])
                            client_socket.sendall(blockchain_data.encode())
                            logging.info(f"Sent blockchain to peer at {address}")

                        elif request_parts[0] == "REQUEST_PEER_LIST" and request_parts[1] == ACCESS_TOKEN:
                            peer_list = ",".join(blockchain.peers)
                            client_socket.sendall(peer_list.encode())
                            logging.info(f"Sent peer list to peer at {address}")

                        elif request_parts[0] == "NEW_TRANSACTION":
                            # Deserialize transaction and add to mempool
                            transaction_data = json.loads(request_parts[1])
                            transaction = Transaction(**transaction_data)
                            if blockchain.add_transaction(transaction):
                                logging.info(f"Received and added new transaction from {address}")
                            else:
                                logging.warning(f"Failed to add transaction from {address}")

                        elif request_parts[0] == "NEW_BLOCK":
                            # Deserialize block and validate
                            block_data = json.loads(request_parts[1])
                            new_block = blockchain.dict_to_block(block_data)
                            if blockchain.is_block_valid(new_block):
                                blockchain.add_block(new_block)
                                logging.info(f"Received and added new block from {address}")
                            else:
                                logging.warning(f"Invalid block received from {address}")

                        elif request_parts[0] == "HANDSHAKE":
                            # Basic handshake for compatibility check
                            client_socket.sendall(b"HANDSHAKE_OK")
                            logging.info(f"Handshake successful with {address}")

                        else:
                            logging.warning(f"Unauthorized access attempt from {address}")
                            client_socket.sendall(b"ACCESS_DENIED")
                except Exception as e:
                    logging.error(f"Error handling client connection: {e}")


def rate_limit_check(ip, command):
    """Check if the given IP address exceeds the rate limit for a specific command."""
    current_time = datetime.now()
    request_times = rate_limit_tracker[ip][command]
    
    # Remove outdated requests
    rate_limit_tracker[ip][command] = [t for t in request_times if current_time - t < RATE_LIMIT_WINDOW]
    
    # Check current rate
    if len(rate_limit_tracker[ip][command]) >= MAX_REQUESTS_PER_WINDOW:
        return False
    
    # Log new request
    rate_limit_tracker[ip][command].append(current_time)
    return True

class Blockchain:
    def __init__(self, difficulty=2, filename="blockchain.json"):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.filename = filename
        self.load_chain()
        self.block_times = []
        self.peers = set()
        self.mempool = []  # Priority queue (min-heap) for unconfirmed transactions

        # Start peer discovery in a separate thread
        discovery_thread = threading.Thread(target=self.peer_discovery)
        discovery_thread.daemon = True
        discovery_thread.start()

    def cleanup_mempool(self, max_age=600):
        """Removes transactions from the mempool that are older than a specified max age."""
        current_time = time.time()
        cleaned_mempool = []
        removed_count = 0

        while self.mempool:
            priority, transaction = heapq.heappop(self.mempool)
            timestamp = priority[1]

            # If the transaction is too old, discard it
            if current_time - timestamp > max_age:
                removed_count += 1
                continue

            # Otherwise, keep it
            cleaned_mempool.append((priority, transaction))

        # Rebuild the mempool
        for item in cleaned_mempool:
            heapq.heappush(self.mempool, item)

        logging.info(f"Cleaned up {removed_count} old transactions from the mempool.")

# Example usage to clean up old transactions every minute

def periodic_cleanup(blockchain, interval=60):
    """Periodically cleans up the mempool to remove old transactions."""
    while True:
        blockchain.cleanup_mempool()
        time.sleep(interval)

# Initialize the blockchain and start the cleanup thread
blockchain = Blockchain(difficulty=2)
cleanup_thread = threading.Thread(target=periodic_cleanup, args=(blockchain,))
cleanup_thread.daemon = True
cleanup_thread.start()

from ecdsa import SigningKey, SECP256k1
from hashlib import sha256
import random

class SchnorrSignature:
    def __init__(self):
        self.private_key = SigningKey.generate(curve=SECP256k1)
        self.public_key = self.private_key.get_verifying_key()

    def sign(self, message):
        """Generate a Schnorr signature for a message."""
        # Generate a random nonce
        k = random.randint(1, SECP256k1.order)
        R = k * SECP256k1.generator  # Commitment
        r = R.x()  # The x-coordinate of R is used as part of the signature

        # Compute the hash of R concatenated with the message
        h = int(sha256((str(r) + message).encode()).hexdigest(), 16)

        # Calculate the signature
        s = (k + h * self.private_key.privkey.secret_multiplier) % SECP256k1.order
        return (r, s)

    def verify(self, message, signature):
        """Verify a Schnorr signature for a message."""
        r, s = signature
        h = int(sha256((str(r) + message).encode()).hexdigest(), 16)

        # Recalculate point from signature
        R = (s * SECP256k1.generator) - (h * self.public_key.pubkey.point)
        return R.x() == r

# Example usage
signer = SchnorrSignature()
message = "This is a BSV batch verification example."
signature = signer.sign(message)
print(f"Signature valid: {signer.verify(message, signature)}")

from ecdsa import VerifyingKey, SECP256k1

class BatchVerifier:
    def __init__(self):
        self.public_keys = []
        self.messages = []
        self.signatures = []

    def add_transaction(self, public_key, message, signature):
        """Add a transaction's public key, message, and signature to the batch."""
        self.public_keys.append(public_key)
        self.messages.append(message)
        self.signatures.append(signature)

    def batch_verify(self):
        """Perform a batch verification of all signatures."""
        total_r = 0
        total_s = 0
        for public_key, message, (r, s) in zip(self.public_keys, self.messages, self.signatures):
            h = int(sha256((str(r) + message).encode()).hexdigest(), 16)
            total_r += h * public_key.pubkey.point
            total_s += s

        # Perform a single verification step with aggregated values
        result = (total_s * SECP256k1.generator) == total_r
        return result

# Example batch usage
batch = BatchVerifier()
# Assuming we have multiple transactions with their public keys, messages, and Schnorr signatures
for i in range(10):
    signer = SchnorrSignature()
    message = f"Transaction {i}"
    signature = signer.sign(message)
    batch.add_transaction(signer.public_key, message, signature)

# Batch verify all transactions
print(f"Batch verification result: {batch.batch_verify()}")

# Enhancing the Blockchain with Improved Block and Chain Validation Checks

import hashlib
import json
import time
import logging
import secrets

# Set up logging to capture blockchain activity during validation
logging.basicConfig(
    filename='blockchain_validation.log',
    filemode='w',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

class Transaction:
    def __init__(self, sender, receiver, amount):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.signature = secrets.token_hex(16)  # Placeholder signature for simplicity

    def __repr__(self):
        return f"Transaction({self.sender} -> {self.receiver}: {self.amount})"

class Block:
    def __init__(self, index, previous_hash, transactions, timestamp=None, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.timestamp = timestamp or int(time.time())
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.previous_hash}{json.dumps([tx.__dict__ for tx in self.transactions])}{self.timestamp}{self.nonce}".encode()
        return hashlib.sha256(block_string).hexdigest()

    def mine_block(self, difficulty):
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()

class Blockchain:
    def __init__(self, difficulty=2):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.pending_transactions = []

    def create_genesis_block(self):
        return Block(0, "0", [], nonce=0)

    def get_latest_block(self):
        return self.chain[-1]

    def add_transaction(self, transaction):
        self.pending_transactions.append(transaction)

    def mine_pending_transactions(self):
        if not self.pending_transactions:
            logging.info("No transactions to mine.")
            return

        new_block = Block(
            index=len(self.chain),
            previous_hash=self.get_latest_block().hash,
            transactions=self.pending_transactions
        )
        
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

        logging.info(f"Block {new_block.index} mined successfully: {new_block.hash}")
        self.pending_transactions = []

    def is_chain_valid(self):
        """Validates the blockchain by checking hashes, previous hashes, and other integrity checks."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # Validate the current block hash
            recalculated_hash = current_block.calculate_hash()
            if current_block.hash != recalculated_hash:
                logging.error(f"Block {i} hash is invalid. Expected: {recalculated_hash}, but found: {current_block.hash}.")
                return False

            # Validate the link between blocks
            if current_block.previous_hash != previous_block.hash:
                logging.error(f"Block {i} has an invalid previous hash. Expected: {previous_block.hash}, but found: {current_block.previous_hash}.")
                return False

            # Verify all transactions are unaltered by checking their structure (simple signature match here)
            for tx in current_block.transactions:
                if not tx.signature or len(tx.signature) != 32:
                    logging.error(f"Block {i} contains a tampered transaction from {tx.sender} to {tx.receiver}.")
                    return False

        logging.info("Blockchain validation complete: all blocks are valid.")
        return True

# Testing the enhanced blockchain with added validation
# Instantiate blockchain

test_blockchain = Blockchain(difficulty=2)

# Create and add transactions to blockchain
transaction1 = Transaction(
    sender="Alice",
    receiver="Bob",
    amount=10
)

transaction2 = Transaction(
    sender="Bob",
    receiver="Charlie",
    amount=5
)

# Adding transactions to the blockchain

test_blockchain.add_transaction(transaction1)
test_blockchain.add_transaction(transaction2)

# Mine the transactions in a block
test_blockchain.mine_pending_transactions()

# Adding more transactions and mining a new block
transaction3 = Transaction(
    sender="Charlie",
    receiver="Alice",
    amount=3
)

test_blockchain.add_transaction(transaction3)
test_blockchain.mine_pending_transactions()

# Validate the chain to check for any inconsistencies
chain_is_valid = test_blockchain.is_chain_valid()
logging.info(f"Is the blockchain valid? {chain_is_valid}")

# Output the blockchain state for validation purposes
blockchain_state = [
    {
        "index": block.index,
        "previous_hash": block.previous_hash,
        "hash": block.hash,
        "transactions": [tx.__dict__ for tx in block.transactions]
    }
    for block in test_blockchain.chain
]

from ecdsa import SigningKey, VerifyingKey, SECP256k1

class Transaction:
    def __init__(self, sender_public_key, receiver, amount):
        self.sender_public_key = sender_public_key  # Public key in PEM format
        self.receiver = receiver
        self.amount = amount
        self.signature = None

    def sign_transaction(self, sender_private_key):
        """Sign the transaction with the sender's private key."""
        transaction_data = f"{self.sender_public_key}{self.receiver}{self.amount}".encode()
        self.signature = sender_private_key.sign(transaction_data)

    def is_valid(self):
        """Verify the transaction signature."""
        if not self.signature:
            return False
        transaction_data = f"{self.sender_public_key}{self.receiver}{self.amount}".encode()
        sender_vk = VerifyingKey.from_string(bytes.fromhex(self.sender_public_key), curve=SECP256k1)
        return sender_vk.verify(self.signature, transaction_data)
def is_chain_valid(self):
    for i in range(1, len(self.chain)):
        current_block = self.chain[i]
        previous_block = self.chain[i - 1]

        # Hash and link checks (same as before)...

        # Verify all transactions
        for tx in current_block.transactions:
            if not tx.is_valid():
                logging.error(f"Invalid transaction detected in block {i}.")
                return False
    logging.info("Blockchain validation complete: all blocks are valid.")
    return True
