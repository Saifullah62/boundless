# Full Integrated Blockchain Script with Improvements

import hashlib
import time
import json
import os
import logging
import socket
import ssl
import secrets
from collections import defaultdict
from datetime import datetime, timedelta
import heapq
import threading
import random
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(
    filename='blockchain.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# Load environment variables
load_dotenv()

# Network constants for peer-to-peer communication
PORT = 5000
BUFFER_SIZE = 4096
ACCESS_TOKEN = os.getenv("ACCESS_TOKEN", secrets.token_hex(16))

# Blockchain Implementation
class Blockchain:
    def __init__(self, difficulty=2, filename="blockchain.json"):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.filename = filename
        self.block_times = []  # Track mining times for blocks
        self.peers = set()  # Set of known peer addresses
        self.mempool = []  # Priority queue (min-heap) for unconfirmed transactions
        self.balances = {"Alice": 100, "Bob": 50}  # Mocked balance sheet for validation
        self.peer_lock = threading.Lock()  # Synchronization lock for peer discovery
        self.rate_limiter = RateLimiter()  # Initialize rate limiter for request management

        # Load blockchain from file if it exists
        self.load_chain()

        # Initiate initial sync with peers
        self.initial_sync()

        # Start peer synchronization in a separate thread using the PeerSyncThread class
        self.peer_sync_thread = PeerSyncThread(
            self.peers, self.peer_lock, self.connect_to_blockchain
        )
        self.peer_sync_thread.start()

    def create_genesis_block(self):
        return Block(0, "0", [], nonce=0)

    def get_latest_block(self):
        return self.chain[-1]
    def add_block(self, new_block):
        new_block.previous_hash = self.get_latest_block().hash
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)
        logging.info(f"Block {new_block.index} added to chain with hash: {new_block.hash}")
        self.save_chain()

    def verify_transaction(self, transaction):
        """Verifies if a transaction is valid based on the sender's balance and signature, and prevents double-spending."""
        sender_balance = self.balances.get(transaction.sender, 0)
        
        # Check if the transaction is already part of a confirmed block to prevent double-spending
        for block in self.chain:
            for tx in block.transactions:
                if (tx.sender == transaction.sender and tx.amount == transaction.amount 
                        and tx.receiver == transaction.receiver):
                    logging.warning(f"Double-spending detected: Transaction from {transaction.sender} "
                                    f"to {transaction.receiver} already exists.")
                    return False

        if sender_balance >= transaction.amount + transaction.fee and transaction.verify_signature(self.get_public_key(transaction.sender)):
            return True
        else:
            logging.warning(f"Transaction from {transaction.sender} to {transaction.receiver} is invalid due to insufficient balance or invalid signature.")
            return False

    def add_transaction(self, transaction):
        """Adds a transaction to the mempool after verifying it."""
        if self.verify_transaction(transaction):
            priority = (-transaction.fee, time.time(), transaction)  # Use fee and timestamp for prioritization
            heapq.heappush(self.mempool, priority)
            logging.info(f"Transaction {transaction} added to the mempool.")
        else:
            logging.warning(f"Transaction {transaction} was not added to the mempool due to verification failure.")

    def mine_new_block(self):
        """Selects transactions from the mempool and mines a new block."""
        if not self.mempool:
            logging.info("No transactions to mine.")
            return

        selected_transactions = []
        while self.mempool and len(selected_transactions) < 10:
            _, _, transaction = heapq.heappop(self.mempool)
            selected_transactions.append(transaction)

            # Deduct the amount and fee from the sender's balance
            self.balances[transaction.sender] -= (transaction.amount + transaction.fee)

            # Add the amount to the receiver's balance
            self.balances[transaction.receiver] = self.balances.get(transaction.receiver, 0) + transaction.amount

        # Create and mine a new block
        new_block = Block(len(self.chain), self.get_latest_block().hash, selected_transactions)
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)
        logging.info(f"Block {new_block.index} mined with hash: {new_block.hash}")
        self.save_chain()

    def initial_sync(self):
        """Performs an initial synchronization with known peers to ensure the blockchain is up to date."""
        logging.info("Starting initial sync process with known peers...")
        longest_chain = self.chain
        max_length = len(self.chain)

        for peer in list(self.peers):
            try:
                peer_chain = self.get_chain_from_peer(peer)
                if len(peer_chain) > max_length and self.is_valid_chain(peer_chain):
                    max_length = len(peer_chain)
                    longest_chain = peer_chain
            except Exception as e:
                logging.error(f"Error retrieving chain from peer {peer} during initial sync: {e}")

        if longest_chain != self.chain:
            logging.info("Replacing current chain with the longest valid chain found during initial sync.")
            self.chain = longest_chain
            self.save_chain()

    def get_chain_from_peer(self, peer):
        """Connects to a peer and retrieves their blockchain to check for a longer chain."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile="trusted-certs.pem")
        with socket.create_connection((peer.split(':')[0], int(peer.split(':')[1])), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=peer) as s:
                s.sendall(f"REQUEST_BLOCKCHAIN|{ACCESS_TOKEN}".encode())
                data = b""
                while True:
                    part = s.recv(BUFFER_SIZE)
                    if not part:
                        break
                    data += part
                return [self.dict_to_block(block) for block in json.loads(data.decode())]

    def connect_to_blockchain(self, host):
        """Connect to a peer's blockchain and sync if their chain is longer."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cafile="trusted-certs.pem")
            with socket.create_connection((host.split(':')[0], int(host.split(':')[1])), timeout=10) as sock:
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
                        self.chain = received_chain_objects
                        self.save_chain()
                        logging.info("Replacing current blockchain with the received chain.")
                    else:
                        logging.info("Received blockchain is not valid or shorter. No update performed.")
        except socket.error as e:
            logging.error(f"Failed to connect to {host}:{PORT} - {e}")
        except json.JSONDecodeError as e:
            logging.error(f"Failed to decode blockchain JSON data from {host}:{PORT} - {e}")
        except Exception as e:
            logging.error(f"Unexpected error while connecting to blockchain: {e}")

    def resolve_conflicts(self):
        """Implements a consensus algorithm to resolve conflicts by adopting the chain with the highest cumulative proof-of-work."""
        logging.info("Resolving chain conflicts...")
        best_chain = self.chain
        best_cumulative_difficulty = self.calculate_cumulative_difficulty(self.chain)

        for peer in list(self.peers):
            try:
                peer_chain = self.get_chain_from_peer(peer)
                if self.is_valid_chain(peer_chain):
                    peer_cumulative_difficulty = self.calculate_cumulative_difficulty(peer_chain)
                    if peer_cumulative_difficulty > best_cumulative_difficulty:
                        best_chain = peer_chain
                        best_cumulative_difficulty = peer_cumulative_difficulty
            except Exception as e:
                logging.error(f"Error retrieving chain from peer {peer}: {e}")

        if best_chain != self.chain:
            logging.info("Replacing current chain with the chain with the highest cumulative proof-of-work.")
            self.chain = best_chain
            self.save_chain()

    def calculate_cumulative_difficulty(self, chain):
        """Calculates the cumulative difficulty for a given chain based on the block difficulty."""
        return sum(block.difficulty for block in chain)

    def save_chain(self):
        """Saves the blockchain to a JSON file to ensure persistence."""
        try:
            with open(self.filename, "w") as f:
                json.dump([self.block_to_dict(block) for block in self.chain], f, indent=4)
            logging.info("Blockchain saved successfully.")
        except (IOError, Exception) as e:
            logging.error(f"Failed to save blockchain to file: {e}")

    def load_chain(self):
        """Loads the blockchain from a JSON file if it exists."""
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

    def is_valid_chain(self, chain):
        """Validates the entire blockchain by verifying hashes, previous hashes, and transaction signatures."""
        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i - 1]

            # Verify block hash
            if current_block.hash != current_block.calculate_hash():
                logging.error(f"Invalid block at index {i}: hash mismatch.")
                return False

            # Verify previous hash
            if current_block.previous_hash != previous_block.hash:
                logging.error(f"Invalid block at index {i}: previous hash mismatch.")
                return False

            # Verify all transactions within the block
            for transaction in current_block.transactions:
                if not transaction.verify_signature(self.get_public_key(transaction.sender)):
                    logging.error(f"Invalid signature for transaction {transaction}")
                    return False

        return True

    def block_to_dict(self, block):
        """Converts a block to a dictionary representation for easy JSON serialization."""
        return {
            "index": block.index,
            "previous_hash": block.previous_hash,
            "transactions": [tx.to_dict() for tx in block.transactions],
            "timestamp": block.timestamp,
            "nonce": block.nonce,
            "merkle_root": getattr(block, 'merkle_root', None),
            "hash": block.hash
        }

    def dict_to_block(self, block_dict):
        """Converts a dictionary representation back to a Block object."""
        transactions = [Transaction(**tx) for tx in block_dict["transactions"]]
        block = Block(block_dict["index"], block_dict["previous_hash"], transactions,
                      block_dict["timestamp"], block_dict["nonce"])
        block.hash = block_dict["hash"]
        return block

    def get_public_key(self, public_key_pem):
        """Deserializes a public key from PEM format to use it for transaction verification."""
        try:
            return serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        except ValueError as e:
            logging.error(f"Failed to load public key: {e}")
            raise

    def handle_peer_request(self, ip, command):
        """Handles requests from peers, enforcing rate limits to prevent abuse."""
        if self.rate_limiter.is_rate_limited(ip, command):
            return "RATE_LIMIT_EXCEEDED"

        # Handle the command as required (implementation could go here)
        return "COMMAND_HANDLED"

    def add_peer(self, peer):
        """Adds a peer to the peer set, ensuring no duplicate entries."""
        with self.peer_lock:
            if peer not in self.peers:
                self.peers.add(peer)
                logging.info(f"Peer {peer} added successfully.")

    def peer_discovery(self):
        """Handles the peer discovery process periodically to expand the network."""
        logging.info("Peer discovery process started...")
        while True:
            if len(self.peers) > 0:
                with self.peer_lock:
                    selected_peer = random.choice(list(self.peers))
                self.request_peers_from_peer(selected_peer)
            time.sleep(60 + random.uniform(-5, 5))  # Adding some randomness to avoid synchronization issues

    def request_peers_from_peer(self, peer):
        """Requests known peers from another peer to enhance network connectivity."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((peer.split(':')[0], int(peer.split(':')[1])), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=peer) as s:
                    s.sendall(f"REQUEST_PEER_LIST|{ACCESS_TOKEN}".encode())
                    data = s.recv(BUFFER_SIZE).decode()
                    received_peers = data.split(',')
                    for new_peer in received_peers:
                        if new_peer not in self.peers and new_peer != peer:
                            logging.info(f"Discovered new peer: {new_peer}")
                            self.peers.add(new_peer)
        except (socket.error, ssl.SSLError) as e:
            logging.error(f"Failed to request peers from {peer}: {e}")

    def stop_peer_discovery(self):
        """Stops the peer discovery process gracefully."""
        logging.info("Stopping peer discovery process...")

class Transaction:
    """Base class representing a transaction in the blockchain."""

    def __init__(self, sender, receiver, amount, fee=0, tx_type="standard", private_key=None, metadata=None):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.fee = fee
        self.tx_type = tx_type
        self.metadata = metadata or {}
        self.signature = None

        # Automatically sign the transaction if a private key is provided
        if private_key:
            self.sign_transaction(private_key)

    def __repr__(self):
        return f"{self.tx_type.capitalize()}Transaction({self.sender} -> {self.receiver}: {self.amount}, Fee: {self.fee})"

    def to_dict(self):
        """Converts the transaction to a dictionary representation."""
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "fee": self.fee,
            "tx_type": self.tx_type,
            "metadata": self.metadata,
            "signature": self.signature.hex() if self.signature else None
        }

    def sign_transaction(self, private_key):
        """Signs the transaction using the sender's private key."""
        transaction_data = f"{self.sender}{self.receiver}{self.amount}{self.fee}{self.tx_type}{json.dumps(self.metadata)}".encode()
        self.signature = private_key.sign(transaction_data, ec.ECDSA(hashes.SHA256()))

    def verify_signature(self, public_key):
        """Verifies the transaction's signature."""
        transaction_data = f"{self.sender}{self.receiver}{self.amount}{self.fee}{self.tx_type}{json.dumps(self.metadata)}".encode()
        try:
            public_key.verify(self.signature, transaction_data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            logging.warning(f"Invalid signature for {self.tx_type} transaction from {self.sender} to {self.receiver}.")
            return False


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

    def mine_block(self, difficulty, callback=None):
        """Mines the block by finding a hash that meets the difficulty target."""
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()

        # If a callback is provided, call it once the block is mined
        if callback:
            callback(self)


class MerkleTree:
    """Constructs a Merkle Tree from a list of transactions."""

    def __init__(self, transactions):
        self.transactions = transactions
        self.root = self.build_tree([self.hash_data(str(tx)) for tx in transactions])

    @staticmethod
    def hash_data(data):
        """Hashes the given data using SHA-512."""
        return hashlib.sha512(data.encode()).digest()

    def build_tree(self, leaves):
        """Builds the Merkle Tree iteratively from the leaves."""
        while len(leaves) > 1:
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1][:])  # Make a copy to avoid reference issues
            parent_layer = [self.hash_data(leaves[i] + leaves[i + 1]) for i in range(0, len(leaves), 2)]
            leaves = parent_layer
        return leaves[0] if leaves else None


class PeerDiscoveryThread(threading.Thread):
    """
    Thread to handle peer discovery in the blockchain network.
    """
    def __init__(self, peers, peer_lock, request_peers_callback):
        super(PeerDiscoveryThread, self).__init__()
        self.peers = peers
        self.peer_lock = peer_lock
        self.request_peers_callback = request_peers_callback
        self.daemon = True  # Ensure thread exits when main program ends
        self.stop_event = threading.Event()  # To allow graceful stopping

    def run(self):
        logging.info("Peer discovery thread started...")
        while not self.stop_event.is_set():
            if len(self.peers) > 0:
                with self.peer_lock:
                    selected_peer = random.choice(list(self.peers))
                self.request_peers_callback(selected_peer)
            time.sleep(60 + random.uniform(-5, 5))  # Adding some randomness to avoid synchronization issues

    def stop(self):
        """Stops the peer discovery thread gracefully."""
        self.stop_event.set()


class PeerSyncThread(threading.Thread):
    """
    Thread to handle synchronization with peer blockchains in the network.
    """
    def __init__(self, peers, peer_lock, connect_to_blockchain_callback):
        super(PeerSyncThread, self).__init__()
        self.peers = peers
        self.peer_lock = peer_lock
        self.connect_to_blockchain_callback = connect_to_blockchain_callback
        self.daemon = True  # Ensure thread exits when main program ends
        self.stop_event = threading.Event()  # To allow graceful stopping

    def run(self):
        logging.info("Peer sync thread started...")
        while not self.stop_event.is_set():
            if len(self.peers) > 0:
                with self.peer_lock:
                    selected_peer = random.choice(list(self.peers))
                self.connect_to_blockchain_callback(selected_peer)
            time.sleep(30)  # Sync every 30 seconds

    def stop(self):
        """Stops the peer sync thread gracefully."""
        self.stop_event.set()

class RateLimiter:
    """
    Implements a rate-limiting mechanism for requests to prevent abuse and ensure network fairness.
    """
    RATE_LIMIT_WINDOW = timedelta(seconds=10)  # Rate limiting window
    MAX_REQUESTS_PER_WINDOW = 5

    def __init__(self):
        self.rate_limit_tracker = defaultdict(lambda: defaultdict(list))

    def is_rate_limited(self, ip, command):
        """
        Checks whether the rate limit for a specific IP address and command has been exceeded.
        """
        current_time = datetime.now()
        request_times = self.rate_limit_tracker[ip][command]

        # Remove outdated requests
        self.rate_limit_tracker[ip][command] = [t for t in request_times if current_time - t < self.RATE_LIMIT_WINDOW]

        # Check if the request limit has been exceeded
        if len(self.rate_limit_tracker[ip][command]) >= self.MAX_REQUESTS_PER_WINDOW:
            logging.warning(f"Rate limit exceeded for {ip} on command {command}.")
            return True

        # Add the current request to the list
        self.rate_limit_tracker[ip][command].append(current_time)
        return False


# Adding Utility Methods to Blockchain Class
class Blockchain:
    def __init__(self, difficulty=2, filename="blockchain.json"):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.filename = filename
        self.block_times = []  # Track mining times for blocks
        self.peers = set()  # Set of known peer addresses
        self.mempool = []  # Priority queue (min-heap) for unconfirmed transactions
        self.peer_lock = threading.Lock()  # Synchronization lock for peer discovery
        self.rate_limiter = RateLimiter()  # Initialize rate limiter for request management

        # Load blockchain from file if it exists
        self.load_chain()

        # Initiate initial sync with peers
        self.initial_sync()

        # Start peer synchronization in a separate thread using the PeerSyncThread class
        self.peer_sync_thread = PeerSyncThread(
            self.peers, self.peer_lock, self.connect_to_blockchain
        )
        self.peer_sync_thread.start()

    def stop_peer_sync(self):
        """Stops the peer synchronization process gracefully."""
        self.peer_sync_thread.stop()

    def create_genesis_block(self):
        """Creates the first block in the blockchain."""
        return Block(0, "0", [], nonce=0)

    def handle_peer_request(self, ip, command):
        """Handles a peer request, enforcing rate limits to prevent abuse."""
        if self.rate_limiter.is_rate_limited(ip, command):
            return "RATE_LIMIT_EXCEEDED"

        # Handle the command normally
        # (implementation goes here)
        return "COMMAND_HANDLED"

    def adjust_difficulty(self):
        """Adjusts the mining difficulty based on the average block time."""
        if len(self.block_times) >= 10:
            avg_mining_duration = sum(self.block_times[-10:]) / 10
            target_duration = 180  # Target block time in seconds
            lower_bound = 150  # Lower acceptable bound
            upper_bound = 210  # Upper acceptable bound

            if avg_mining_duration < lower_bound:
                self.difficulty += 1
            elif avg_mining_duration > upper_bound:
                self.difficulty = max(1, self.difficulty - 1)
            else:
                adjustment_factor = avg_mining_duration / target_duration
                if adjustment_factor < 0.95:
                    self.difficulty = int(self.difficulty * 0.98)
                elif adjustment_factor > 1.05:
                    self.difficulty = max(1, int(self.difficulty / 1.02))

            logging.info(f"Adjusted mining difficulty to {self.difficulty}.")

    def is_valid_chain(self, chain):
        """Check if a given chain is valid by verifying hashes, previous hashes, and transaction signatures."""
        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i - 1]
            if current_block.hash != current_block.calculate_hash():
                logging.error(f"Invalid block at index {i}: hash mismatch.")
                return False
            if current_block.previous_hash != previous_block.hash:
                logging.error(f"Invalid block at index {i}: previous hash mismatch.")
                return False
            # Verify all transactions within the block
            for transaction in current_block.transactions:
                if not transaction.verify_signature(self.get_public_key(transaction.sender)):
                    logging.error(f"Invalid signature for transaction {transaction}")
                    return False
        return True

    def cleanup_mempool(self):
        """Cleans up the mempool by removing invalid or expired transactions."""
        current_time = time.time()
        valid_transactions = []

        for _, _, transaction in self.mempool:
            # Check if the transaction is still valid (e.g., timestamp is within acceptable range)
            if transaction.timestamp > current_time - 3600:  # 1-hour validity
                valid_transactions.append((_, _, transaction))

        self.mempool = valid_transactions  # Update mempool with valid transactions


# Block-to-Dictionary and Dictionary-to-Block Utilities
    @staticmethod
    def block_to_dict(block):
        """Converts a block to a dictionary representation."""
        return {
            "index": block.index,
            "previous_hash": block.previous_hash,
            "transactions": [tx.to_dict() for tx in block.transactions],
            "timestamp": block.timestamp,
            "nonce": block.nonce,
            "merkle_root": getattr(block, 'merkle_root', None),
            "hash": block.hash
        }

    def dict_to_block(self, block_dict):
        """Converts a dictionary representation back to a block."""
        transactions = [Transaction(**tx) for tx in block_dict["transactions"]]
        block = Block(block_dict["index"], block_dict["previous_hash"], transactions,
                      block_dict["timestamp"], block_dict["nonce"])
        block.hash = block_dict["hash"]
        return block

    def get_public_key(self, public_key_pem):
        """Deserializes a public key from PEM format."""
        try:
            return serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        except ValueError as e:
            logging.error(f"Failed to load public key: {e}")
            raise

class Transaction:
    """Base class representing a transaction in the blockchain."""

    def __init__(self, sender, receiver, amount, fee=0, tx_type="standard", private_key=None, metadata=None):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.fee = fee  # Transaction fee
        self.tx_type = tx_type  # Defines the transaction type (standard, contract, asset, etc.)
        self.metadata = metadata or {}  # Optional metadata for additional information
        self.timestamp = time.time()  # Timestamp for when the transaction is created
        self.signature = None

        # Auto-sign the transaction if a private key is provided
        if private_key:
            self.sign_transaction(private_key)

    def __repr__(self):
        return f"{self.tx_type.capitalize()}Transaction({self.sender} -> {self.receiver}: {self.amount}, Fee: {self.fee})"

    def to_dict(self):
        """Converts the transaction to a dictionary representation."""
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "fee": self.fee,
            "tx_type": self.tx_type,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
            "signature": self.signature.hex() if self.signature else None
        }

    def sign_transaction(self, private_key):
        """Signs the transaction using the sender's private key."""
        transaction_data = f"{self.sender}{self.receiver}{self.amount}{self.fee}{self.tx_type}{json.dumps(self.metadata)}".encode()
        self.signature = private_key.sign(transaction_data, ec.ECDSA(hashes.SHA256()))

    def verify_signature(self, public_key):
        """Verifies the transaction signature."""
        transaction_data = f"{self.sender}{self.receiver}{self.amount}{self.fee}{self.tx_type}{json.dumps(self.metadata)}".encode()
        try:
            public_key.verify(self.signature, transaction_data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            logging.warning(f"Invalid signature for {self.tx_type} transaction from {self.sender} to {self.receiver}.")
            return False


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
        self.difficulty = 0  # Track the difficulty of the mined block

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
        self.difficulty = difficulty  # Assign the difficulty level used for mining
        logging.info(f"Block {self.index} mined with nonce: {self.nonce} and hash: {self.hash}")


class MerkleTree:
    """Constructs a Merkle Tree from a list of transactions."""

    def __init__(self, transactions):
        self.transactions = transactions
        self.root = self.build_tree([self.hash_data(str(tx)) for tx in transactions])

    @staticmethod
    def hash_data(data):
        """Hashes the given data using SHA-512."""
        return hashlib.sha512(data.encode()).digest()

    def build_tree(self, leaves):
        """Builds the Merkle Tree iteratively from the leaves."""
        while len(leaves) > 1:
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1][:])  # Make a copy to avoid reference issues
            parent_layer = [self.hash_data(leaves[i] + leaves[i + 1]) for i in range(0, len(leaves), 2)]
            leaves = parent_layer
        return leaves[0] if leaves else None


# Adding the PeerSyncThread Class for Peer Synchronization
class PeerSyncThread(threading.Thread):
    """
    Thread to handle synchronization with peer blockchains in the network.
    """

    def __init__(self, peers, peer_lock, connect_to_blockchain_callback):
        super(PeerSyncThread, self).__init__()
        self.peers = peers
        self.peer_lock = peer_lock
        self.connect_to_blockchain_callback = connect_to_blockchain_callback
        self.daemon = True  # Ensure thread exits when main program ends
        self.stop_event = threading.Event()  # To allow graceful stopping

    def run(self):
        logging.info("Peer sync thread started...")
        while not self.stop_event.is_set():
            if len(self.peers) > 0:
                with self.peer_lock:
                    selected_peer = random.choice(list(self.peers))
                self.connect_to_blockchain_callback(selected_peer)
            time.sleep(30)  # Sync every 30 seconds for now

    def stop(self):
        """Stops the peer sync thread gracefully."""
        self.stop_event.set()

# Rate Limiter Class for Preventing Abuse
class RateLimiter:
    """
    Implements a rate-limiting mechanism for requests to prevent abuse and ensure network fairness.
    """
    RATE_LIMIT_WINDOW = timedelta(seconds=10)  # Rate limiting window
    MAX_REQUESTS_PER_WINDOW = 5

    def __init__(self):
        self.rate_limit_tracker = defaultdict(lambda: defaultdict(list))

    def is_rate_limited(self, ip, command):
        """
        Checks whether the rate limit for a specific IP address and command has been exceeded.
        """
        current_time = datetime.now()
        request_times = self.rate_limit_tracker[ip][command]

        # Remove outdated requests
        self.rate_limit_tracker[ip][command] = [t for t in request_times if current_time - t < self.RATE_LIMIT_WINDOW]

        # Check if the request limit has been exceeded
        if len(self.rate_limit_tracker[ip][command]) >= self.MAX_REQUESTS_PER_WINDOW:
            logging.warning(f"Rate limit exceeded for {ip} on command {command}.")
            return True

        # Add the current request to the list
        self.rate_limit_tracker[ip][command].append(current_time)
        return False


class Blockchain:
    """
    Represents the blockchain itself, managing the chain of blocks.
    """
    def __init__(self, difficulty=2, filename="blockchain.json"):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.filename = filename
        self.block_times = []  # Track mining times for blocks
        self.peers = set()  # Set of known peer addresses
        self.mempool = []  # Priority queue (min-heap) for unconfirmed transactions
        self.peer_lock = threading.Lock()  # Synchronization lock for peer discovery
        self.rate_limiter = RateLimiter()  # Initialize rate limiter for request management

        # Load blockchain from file if it exists
        self.load_chain()

        # Initiate initial sync with peers
        self.initial_sync()

        # Start peer synchronization in a separate thread using the PeerSyncThread class
        self.peer_sync_thread = PeerSyncThread(
            self.peers, self.peer_lock, self.connect_to_blockchain
        )
        self.peer_sync_thread.start()

    def stop_peer_sync(self):
        """Stops the peer synchronization process gracefully."""
        self.peer_sync_thread.stop()

    def create_genesis_block(self):
        """Creates the first block in the blockchain."""
        return Block(0, "0", [], nonce=0)

    def dict_to_block(self, block_dict):
        """Converts a dictionary representation back to a block."""
        transactions = [Transaction(**tx) for tx in block_dict["transactions"]]
        block = Block(block_dict["index"], block_dict["previous_hash"], transactions,
                      block_dict["timestamp"], block_dict["nonce"])
        block.hash = block_dict["hash"]
        block.difficulty = block_dict.get("difficulty", 0)
        return block

    def block_to_dict(self, block):
        """Converts a block to a dictionary representation."""
        return {
            "index": block.index,
            "previous_hash": block.previous_hash,
            "transactions": [tx.to_dict() for tx in block.transactions],
            "timestamp": block.timestamp,
            "nonce": block.nonce,
            "merkle_root": getattr(block, 'merkle_root', None),
            "hash": block.hash,
            "difficulty": block.difficulty
        }

    def is_valid_chain(self, chain):
        """Validates the entire blockchain by verifying hashes, previous hashes, and transaction signatures."""
        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i - 1]

            # Check if current block hash is correct
            if current_block.hash != current_block.calculate_hash():
                logging.error(f"Invalid block at index {i}: hash mismatch.")
                return False

            # Ensure the current block's `previous_hash` matches the previous block's hash
            if current_block.previous_hash != previous_block.hash:
                logging.error(f"Invalid block at index {i}: previous hash mismatch.")
                return False

            # Verify all transactions within the block
            for transaction in current_block.transactions:
                if not transaction.verify_signature(self.get_public_key(transaction.sender)):
                    logging.error(f"Invalid signature for transaction {transaction}")
                    return False

        logging.info("Chain validated successfully.")
        return True

    def get_public_key(self, public_key_pem):
        """Deserializes a public key from PEM format."""
        try:
            return serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        except ValueError as e:
            logging.error(f"Failed to load public key: {e}")
            raise

    def cleanup_mempool(self):
        """Cleans up the mempool by removing invalid or expired transactions."""
        current_time = time.time()
        valid_transactions = []

        for _, _, transaction in self.mempool:
            # Check if the transaction is still valid (e.g., timestamp is within acceptable range)
            if transaction.timestamp > current_time - 3600:  # 1-hour validity
                valid_transactions.append((_, _, transaction))

        self.mempool = valid_transactions  # Update mempool with valid transactions

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

# Block Class representing a Block in the Blockchain
class Block:
    """
    Represents a block in the blockchain.
    """
    def __init__(self, index, previous_hash, transactions, timestamp=None, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.timestamp = timestamp or int(time.time())
        self.nonce = nonce
        self.merkle_root = MerkleTree(transactions).root
        self.hash = self.calculate_hash()
        self.difficulty = 1  # Default difficulty for PoW

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

        logging.info(f"Block {self.index} mined: {self.hash}")


# Merkle Tree Class to handle Transactions' Merkle Root Calculation
class MerkleTree:
    """
    Constructs a Merkle Tree from a list of transactions.
    """
    def __init__(self, transactions):
        self.transactions = transactions
        self.root = self.build_tree([self.hash_data(str(tx)) for tx in transactions])

    @staticmethod
    def hash_data(data):
        """Hashes the given data using SHA-512."""
        return hashlib.sha512(data.encode()).digest()

    def build_tree(self, leaves):
        """Builds the Merkle Tree iteratively from the leaves."""
        while len(leaves) > 1:
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1][:])  # Make a copy to avoid reference issues
            parent_layer = [self.hash_data(leaves[i] + leaves[i + 1]) for i in range(0, len(leaves), 2)]
            leaves = parent_layer
        return leaves[0] if leaves else None


# Transaction Classes

class Transaction:
    """
    Base class representing a transaction in the blockchain.
    """
    def __init__(self, sender, receiver, amount, fee=0, tx_type="standard", private_key=None, metadata=None):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.fee = fee
        self.tx_type = tx_type  # Defines the transaction type (standard, contract, asset, etc.)
        self.metadata = metadata or {}  # Optional metadata for additional information
        self.signature = None
        self.timestamp = time.time()  # Add a timestamp for transaction validity checks

        # Auto-sign the transaction if a private key is provided
        if private_key:
            self.sign_transaction(private_key)

    def __repr__(self):
        return f"{self.tx_type.capitalize()}Transaction({self.sender} -> {self.receiver}: {self.amount}, Fee: {self.fee})"

    def to_dict(self):
        """Converts the transaction to a dictionary representation."""
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "fee": self.fee,
            "tx_type": self.tx_type,
            "metadata": self.metadata,
            "signature": self.signature.hex() if self.signature else None,
            "timestamp": self.timestamp
        }

    def sign_transaction(self, private_key):
        """Signs the transaction using the sender's private key."""
        transaction_data = f"{self.sender}{self.receiver}{self.amount}{self.fee}{self.tx_type}{json.dumps(self.metadata)}".encode()
        self.signature = private_key.sign(transaction_data, ec.ECDSA(hashes.SHA256()))

    def verify_signature(self, public_key):
        """Verifies the transaction signature."""
        transaction_data = f"{self.sender}{self.receiver}{self.amount}{self.fee}{self.tx_type}{json.dumps(self.metadata)}".encode()
        try:
            public_key.verify(self.signature, transaction_data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            logging.warning(f"Invalid signature for {self.tx_type} transaction from {self.sender} to {self.receiver}.")
            return False


# MultiSigTransaction Class for Multisignature Transactions
class MultiSigTransaction(Transaction):
    """
    Represents a multi-signature transaction in the blockchain.
    """
    def __init__(self, sender, receiver, amount, required_signatures=2):
        super().__init__(sender, receiver, amount, tx_type="multisig")
        self.required_signatures = required_signatures
        self.signatures = []

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

            if valid_signatures >= self.required_signatures:
                return True

        return False

import datetime
from collections import defaultdict

class RateLimiter:
    """
    Implements a rate-limiting mechanism for requests to prevent abuse and ensure network fairness.
    """
    RATE_LIMIT_WINDOW = datetime.timedelta(seconds=10)  # Rate limiting window
    MAX_REQUESTS_PER_WINDOW = 5

    def __init__(self):
        self.rate_limit_tracker = defaultdict(lambda: defaultdict(list))

    def is_rate_limited(self, ip, command):
        """
        Checks whether the rate limit for a specific IP address and command has been exceeded.
        """
        current_time = datetime.datetime.now()
        request_times = self.rate_limit_tracker[ip][command]

        # Remove outdated requests
        self.rate_limit_tracker[ip][command] = [t for t in request_times if current_time - t < self.RATE_LIMIT_WINDOW]

        # Check if the request limit has been exceeded
        if len(self.rate_limit_tracker[ip][command]) >= self.MAX_REQUESTS_PER_WINDOW:
            logging.warning(f"Rate limit exceeded for {ip} on command {command}.")
            return True

        # Add the current request to the list
        self.rate_limit_tracker[ip][command].append(current_time)
        return False


class PeerSyncThread(threading.Thread):
    """
    Thread to handle synchronization with peer blockchains in the network.
    """
    def __init__(self, peers, peer_lock, connect_to_blockchain_callback):
        super(PeerSyncThread, self).__init__()
        self.peers = peers
        self.peer_lock = peer_lock
        self.connect_to_blockchain_callback = connect_to_blockchain_callback
        self.daemon = True  # Ensure thread exits when main program ends
        self.stop_event = threading.Event()  # To allow graceful stopping

    def run(self):
        logging.info("Peer sync thread started...")
        while not self.stop_event.is_set():
            if len(self.peers) > 0:
                with self.peer_lock:
                    selected_peer = random.choice(list(self.peers))
                self.connect_to_blockchain_callback(selected_peer)
            time.sleep(30)  # Sync every 30 seconds for now

    def stop(self):
        """
        Stops the peer sync thread gracefully.
        """
        self.stop_event.set()

# Peer Discovery Thread
class PeerDiscoveryThread(threading.Thread):
    """
    Thread to handle peer discovery in the blockchain network.
    """
    def __init__(self, peers, peer_lock, request_peers_callback):
        super(PeerDiscoveryThread, self).__init__()
        self.peers = peers
        self.peer_lock = peer_lock
        self.request_peers_callback = request_peers_callback
        self.daemon = True  # Ensure thread exits when main program ends
        self.stop_event = threading.Event()  # To allow graceful stopping

    def run(self):
        logging.info("Peer discovery thread started...")
        while not self.stop_event.is_set():
            if len(self.peers) > 0:
                with self.peer_lock:
                    selected_peer = random.choice(list(self.peers))
                self.request_peers_callback(selected_peer)
            time.sleep(60 + random.uniform(-5, 5))  # Adding some randomness to avoid synchronization issues

    def stop(self):
        """
        Stops the peer discovery thread gracefully.
        """
        self.stop_event.set()


# Integrating PeerSyncThread and PeerDiscoveryThread into Blockchain
class Blockchain:
    """
    Represents the blockchain itself, managing the chain of blocks.
    """
    def __init__(self, difficulty=2, filename="blockchain.json"):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.filename = filename
        self.block_times = []  # Track mining times for blocks
        self.peers = set()  # Set of known peer addresses
        self.mempool = []  # Priority queue (min-heap) for unconfirmed transactions
        self.peer_lock = threading.Lock()  # Synchronization lock for peer discovery
        self.rate_limiter = RateLimiter()  # Initialize rate limiter for request management

        # Load blockchain from file if it exists
        self.load_chain()

        # Start peer discovery and synchronization in separate threads
        self.peer_discovery_thread = PeerDiscoveryThread(
            self.peers, self.peer_lock, self.request_peers_from_peer
        )
        self.peer_discovery_thread.start()

        self.peer_sync_thread = PeerSyncThread(
            self.peers, self.peer_lock, self.connect_to_blockchain
        )
        self.peer_sync_thread.start()

    def stop_peer_threads(self):
        """
        Stops the peer synchronization and discovery threads gracefully.
        """
        self.peer_discovery_thread.stop()
        self.peer_sync_thread.stop()

    def request_peers_from_peer(self, peer):
        """
        Connects to a peer and requests their known peers to expand the peer list.
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((peer.split(':')[0], int(peer.split(':')[1])), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=peer) as s:
                    s.sendall(f"REQUEST_PEER_LIST|{ACCESS_TOKEN}".encode())
                    data = s.recv(BUFFER_SIZE).decode()
                    received_peers = data.split(',')
                    for new_peer in received_peers:
                        if new_peer not in self.peers and new_peer != peer:
                            logging.info(f"Discovered new peer: {new_peer}")
                            self.peers.add(new_peer)
        except (socket.error, ssl.SSLError) as e:
            logging.error(f"Failed to request peers from {peer}: {e}")

    def handle_peer_request(self, ip, command):
        """
        Handles a peer request, enforcing rate limits to prevent abuse.
        """
        if self.rate_limiter.is_rate_limited(ip, command):
            return "RATE_LIMIT_EXCEEDED"

        # Handle the command normally
        # (implementation goes here)
        return "COMMAND_HANDLED"
