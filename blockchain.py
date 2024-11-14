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
            return False

class MerkleTree:
    """Constructs a Merkle Tree from a list of transactions."""
    def __init__(self, transactions):
        self.transactions = transactions
        self.root = self.build_tree([self.hash_data(str(tx)) for tx in transactions])

    @staticmethod
    def hash_data(data):
        """Hashes the given data using SHA-512."""
        salt = os.urandom(16)
        return hashlib.sha512(salt + data.encode()).hexdigest()

    def build_tree(self, leaves):
        """Builds the Merkle Tree iteratively from the leaves."""
        while len(leaves) > 1:
            # If odd number of leaves, duplicate the last leaf
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1])
            # Create parent layer by hashing pairs of leaves
            parent_layer = [self.hash_data(leaves[i] + leaves[i + 1]) for i in range(0, len(leaves), 2)]
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

    def create_genesis_block(self):
        """Creates the first block in the blockchain."""
        return Block(0, "0", [], nonce=0)

    def get_latest_block(self):
        """Returns the latest block in the blockchain."""
        return self.chain[-1]

    def add_block(self, new_block):
        """Adds a new block to the blockchain after mining it."""
        new_block.previous_hash = self.get_latest_block().hash
        start_time = time.time()
        new_block.mine_block(self.difficulty)
        end_time = time.time()

        # Record mining duration
        self.block_times.append(end_time - start_time)
        logging.info(f"Block {new_block.index} mined in {end_time - start_time:.2f} seconds with difficulty {self.difficulty}")

        # Adjust difficulty based on average block time over last 10 blocks
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

import random
import threading

class Blockchain:
    def __init__(self, difficulty=2, filename="blockchain.json"):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.filename = filename
        self.load_chain()
        self.block_times = []  # Track mining times for blocks
        self.peers = set()  # Set of known peer addresses (e.g., 'IP:PORT')

        # Start the peer discovery thread
        discovery_thread = threading.Thread(target=self.peer_discovery)
        discovery_thread.daemon = True
        discovery_thread.start()

    def add_peer(self, peer_address):
        """Adds a new peer to the known peers list."""
        self.peers.add(peer_address)

    def peer_discovery(self):
        """Periodically attempts to discover new peers using a gossip protocol."""
        while True:
            if self.peers:
                # Select a random peer to communicate with
                random_peer = random.choice(list(self.peers))
                try:
                    self.exchange_peer_list(random_peer)
                except Exception as e:
                    logging.error(f"Failed to exchange peers with {random_peer}: {e}")
            time.sleep(30)  # Adjust the interval as needed

    def exchange_peer_list(self, peer_address):
        """Sends the current peer list to a peer and receives their peer list."""
        try:
            # Establish a connection
            context = ssl.create_default_context()
            with socket.create_connection((peer_address, PORT)) as sock:
                with context.wrap_socket(sock, server_hostname=peer_address) as s:
                    # Send peer discovery request
                    s.sendall(f"REQUEST_PEER_LIST|{ACCESS_TOKEN}".encode())
                    data = b""
                    while True:
                        part = s.recv(BUFFER_SIZE)
                        if not part:
                            break
                        data += part

                    received_peers = data.decode().split(",")
                    for peer in received_peers:
                        if peer != self.get_self_address():  # Avoid adding self
                            self.peers.add(peer)
        except Exception as e:
            logging.error(f"Error during peer list exchange with {peer_address}: {e}")

    def get_self_address(self):
        """Retrieve the node's own IP address and port."""
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return f"{ip_address}:{PORT}"

# Server modification to handle peer list requests

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

                        # Handle peer list request
                        if len(request_parts) == 2 and request_parts[0] == "REQUEST_PEER_LIST" and request_parts[1] == ACCESS_TOKEN:
                            peer_list = ",".join(blockchain.peers)
                            client_socket.sendall(peer_list.encode())
                            logging.info(f"Sent peer list to peer at {address}")

                        elif len(request_parts) == 2 and request_parts[0] == "REQUEST_BLOCKCHAIN" and request_parts[1] == ACCESS_TOKEN:
                            blockchain_data = json.dumps([blockchain.block_to_dict(block) for block in blockchain.chain])
                            client_socket.sendall(blockchain_data.encode())
                            logging.info(f"Sent blockchain to peer at {address}")

                        else:
                            logging.warning(f"Unauthorized access attempt from {address}")
                            client_socket.sendall(b"ACCESS_DENIED")
                except Exception as e:
                    logging.error(f"Error handling client connection: {e}")

import heapq

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

    def get_mempool_transactions(self):
        """Returns the list of transactions currently in the mempool."""
        return [tx for _, tx in self.mempool]


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


def broadcast_transaction(self, transaction):
    """Broadcasts a new transaction to all known peers with error handling."""
    transaction_data = json.dumps(transaction.to_dict())
    failed_peers = []

    for peer in self.peers:
        try:
            with socket.create_connection((peer, PORT)) as sock:
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=peer) as s:
                    s.sendall(f"NEW_TRANSACTION|{transaction_data}".encode())
                    logging.info(f"Broadcasted transaction to {peer}")
        except Exception as e:
            logging.error(f"Failed to broadcast transaction to {peer}: {e}")
            failed_peers.append(peer)

    # Remove consistently failing peers
    for peer in failed_peers:
        self.peers.remove(peer)
        logging.info(f"Removed unresponsive peer: {peer}")


def broadcast_block(self, block):
    """Broadcasts a new block to all known peers with error handling."""
    block_data = json.dumps(self.block_to_dict(block))
    failed_peers = []

    for peer in self.peers:
        try:
            with socket.create_connection((peer, PORT)) as sock:
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=peer) as s:
                    s.sendall(f"NEW_BLOCK|{block_data}".encode())
                    logging.info(f"Broadcasted block to {peer}")
        except Exception as e:
            logging.error(f"Failed to broadcast block to {peer}: {e}")
            failed_peers.append(peer)

    # Remove unresponsive peers
    for peer in failed_peers:
        self.peers.remove(peer)
        logging.info(f"Removed unresponsive peer: {peer}")

from concurrent.futures import ThreadPoolExecutor

def validate_chain_in_parallel(self):
    """Validates the blockchain in parallel for faster performance on large chains."""
    with ThreadPoolExecutor() as executor:
        # Validate blocks in parallel
        validation_results = executor.map(self.is_block_valid, self.chain[1:])
        return all(validation_results)

class Blockchain:
    def __init__(self, difficulty=2, filename="blockchain.json"):
        # Existing initialization...
        self.validated_block_cache = {}

    def is_block_valid(self, block):
        """Validates a single block, with caching to avoid redundant validation."""
        # Check if block already validated
        if block.index in self.validated_block_cache:
            return self.validated_block_cache[block.index]

        # Validate block hash and previous hash
        if block.hash != block.calculate_hash():
            return False
        if block.previous_hash != self.chain[block.index - 1].hash:
            return False

        # Validate each transaction in the block
        for transaction in block.transactions:
            if not transaction.verify_signature(self.get_public_key(transaction.sender)):
                return False

        # Cache result
        self.validated_block_cache[block.index] = True
        return True

    def is_chain_valid(self):
        """Validates the blockchain using cached and parallel validation."""
        return self.validate_chain_in_parallel()


def request_chain_from_peers(self):
    """Requests chains from multiple peers and selects the most common chain."""
    peer_chains = []

    for peer in self.peers:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((peer, PORT)) as sock:
                with context.wrap_socket(sock, server_hostname=peer) as s:
                    s.sendall(f"REQUEST_BLOCKCHAIN|{ACCESS_TOKEN}".encode())
                    data = b""
                    while True:
                        part = s.recv(BUFFER_SIZE)
                        if not part:
                            break
                        data += part

                    received_chain = json.loads(data.decode())
                    received_chain_objects = [self.dict_to_block(block) for block in received_chain]
                    peer_chains.append(received_chain_objects)

        except (socket.error, json.JSONDecodeError, Exception) as e:
            logging.error(f"Failed to retrieve chain from {peer}: {e}")

    # Find the most common chain among peers
    return self.select_most_common_chain(peer_chains)


def select_most_common_chain(self, peer_chains):
    """Selects the most common chain among peer chains based on majority rule."""
    chain_counts = {}
    
    for chain in peer_chains:
        chain_hash = hashlib.sha256("".join(block.hash for block in chain).encode()).hexdigest()
        if chain_hash in chain_counts:
            chain_counts[chain_hash]['count'] += 1
        else:
            chain_counts[chain_hash] = {'count': 1, 'chain': chain}
    
    # Select the chain with the highest count (consensus)
    most_common_chain = max(chain_counts.values(), key=lambda x: x['count'])['chain']
    return most_common_chain


def sync_with_peer(self):
    """Syncs the blockchain with peers, using multi-round consensus for forks."""
    # Request chains from peers and determine the most common one
    preferred_chain = self.request_chain_from_peers()

    # If a preferred chain is found, evaluate and replace if needed
    self.replace_chain(preferred_chain)
# Adding enhanced functionality to simulate modules like GeoSovereign, RegBlock, and others.

import copy
import random

class GeoSovereign:
    """Handles geographical data compliance."""
    def detect_data_origin(self, transaction):
        # Simulating detection of geographical origin based on sender information
        regions = ["US", "EU", "ASIA"]
        return random.choice(regions)

class RegBlock:
    """Applies regulatory compliance based on GeoSovereign data."""
    def apply_regulations(self, region):
        if region == "US":
            print("Applying US data regulations.")
        elif region == "EU":
            print("Applying GDPR compliance.")
        elif region == "ASIA":
            print("Applying regional Asia-Pacific data laws.")
        # Additional rules could be added for specific compliance needs

class TransparencySuite:
    """Tracks user consent for data usage."""
    def __init__(self):
        self.consent_registry = {}

    def add_consent(self, user, consent_type):
        self.consent_registry[user] = consent_type
        print(f"User {user} consented to {consent_type} usage.")

    def revoke_consent(self, user):
        if user in self.consent_registry:
            del self.consent_registry[user]
            print(f"User {user} revoked their consent.")

class ErasureGuard:
    """Simulates the 'right to be forgotten' for blockchain transactions."""
    def __init__(self):
        self.nullified_transactions = set()

    def nullify_data(self, transaction_id):
        self.nullified_transactions.add(transaction_id)
        print(f"Transaction {transaction_id} has been nullified.")

    def is_data_nullified(self, transaction_id):
        return transaction_id in self.nullified_transactions

class ComplianceAuditToolkit:
    """Performs audits and monitors compliance of the blockchain."""
    def audit(self, blockchain):
        print("Performing compliance audit...")
        for block in blockchain.chain:
            for tx in block.transactions:
                # Placeholder for checking compliance
                print(f"Audit Check: Transaction from {tx.sender} to {tx.receiver}, Amount: {tx.amount}")

# Integrating modules into the blockchain simulation
class BlockchainNodeEnhanced:
    def __init__(self, node_id, difficulty=2):
        self.node_id = node_id
        self.blockchain = Blockchain(difficulty=difficulty)
        self.geosovereign = GeoSovereign()
        self.regblock = RegBlock()
        self.transparency_suite = TransparencySuite()
        self.erasure_guard = ErasureGuard()
        self.audit_toolkit = ComplianceAuditToolkit()
        self.peers = []  # List of peer nodes

    def add_peer(self, peer_node):
        self.peers.append(peer_node)

    def receive_transaction(self, transaction):
        # Determine geographic region
        region = self.geosovereign.detect_data_origin(transaction)
        # Apply regulatory compliance based on detected region
        self.regblock.apply_regulations(region)
        # Add transaction to the blockchain's mempool
        self.blockchain.add_transaction(transaction)

    def mine_block(self):
        # Before mining, check all transactions for user consent via Transparency Suite
        for tx in self.blockchain.mempool:
            if tx.sender in self.transparency_suite.consent_registry:
                if self.transparency_suite.consent_registry[tx.sender] != "approved":
                    print(f"Transaction from {tx.sender} not approved for mining.")
                    self.blockchain.mempool.remove(tx)
        # Proceed with mining
        self.blockchain.mine_block()

    def sync_with_peers(self):
        for peer in self.peers:
            self.replace_chain_if_needed(peer.blockchain)

    def replace_chain_if_needed(self, new_chain):
        # Replace chain if new chain is longer and valid
        if len(new_chain.chain) > len(self.blockchain.chain) and new_chain.is_chain_valid():
            print(f"Node {self.node_id} replaced its chain with a longer one from a peer.")
            self.blockchain = copy.deepcopy(new_chain)

    def perform_audit(self):
        # Use the ComplianceAuditToolkit to audit the blockchain
        self.audit_toolkit.audit(self.blockchain)

# Testing enhanced blockchain simulation
if __name__ == "__main__":
    # Create enhanced blockchain nodes
    node_A = BlockchainNodeEnhanced("A", difficulty=2)
    node_B = BlockchainNodeEnhanced("B", difficulty=2)
    node_C = BlockchainNodeEnhanced("C", difficulty=2)

    # Establish peer connections
    node_A.add_peer(node_B)
    node_A.add_peer(node_C)
    node_B.add_peer(node_A)
    node_B.add_peer(node_C)
    node_C.add_peer(node_A)
    node_C.add_peer(node_B)

    # Generate some transactions
    transactions = [
        Transaction("Alice", "Bob", 10),
        Transaction("Charlie", "David", 20),
        Transaction("Eve", "Frank", 50)
    ]

    # Add user consent for some transactions in Transparency Suite
    node_A.transparency_suite.add_consent("Alice", "approved")
    node_A.transparency_suite.add_consent("Charlie", "approved")

    # Nodes receive transactions
    for tx in transactions:
        node_A.receive_transaction(tx)
        time.sleep(0.5)

    # Nodes mine blocks
    node_A.mine_block()
    node_B.mine_block()
    node_C.mine_block()

    # Perform compliance audit
    node_A.perform_audit()

    # Simulate right to be forgotten
    tx_to_nullify = "Charlie_to_David"
    node_A.erasure_guard.nullify_data(tx_to_nullify)

    # Final state of each blockchain
    for node in [node_A, node_B, node_C]:
        print(f"\nFinal blockchain for Node {node.node_id}:")
        for block in node.blockchain.chain:
            print(f"  Block {block.index} [Hash: {block.hash}, Prev: {block.previous_hash}, Transactions: {len(block.transactions)}]")

from cryptography.fernet import Fernet

# Generate a key for encryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Adding enhanced functionality: Peer-to-peer synchronization and data encryption

class BlockchainNodeSecure:
    def __init__(self, node_id, difficulty=2):
        self.node_id = node_id
        self.blockchain = Blockchain(difficulty=difficulty)
        self.geosovereign = GeoSovereign()
        self.regblock = RegBlock()
        self.transparency_suite = TransparencySuite()
        self.erasure_guard = ErasureGuard()
        self.audit_toolkit = ComplianceAuditToolkit()
        self.peers = []  # List of peer nodes

    def add_peer(self, peer_node):
        self.peers.append(peer_node)

    def receive_transaction(self, transaction):
        # Encrypt transaction data at rest
        transaction_data = json.dumps(transaction.to_dict()).encode()
        encrypted_data = cipher_suite.encrypt(transaction_data)
        transaction.encrypted_data = encrypted_data

        # Determine geographic region for compliance
        region = self.geosovereign.detect_data_origin(transaction)
        # Apply regulatory compliance based on detected region
        self.regblock.apply_regulations(region)
        # Add encrypted transaction to the blockchain's mempool
        self.blockchain.add_transaction(transaction)

    def mine_block(self):
        # Before mining, check all transactions for user consent via Transparency Suite
        for tx in self.blockchain.mempool:
            if tx.sender in self.transparency_suite.consent_registry:
                if self.transparency_suite.consent_registry[tx.sender] != "approved":
                    print(f"Transaction from {tx.sender} not approved for mining.")
                    self.blockchain.mempool.remove(tx)

        # Proceed with mining
        self.blockchain.mine_block()

        # Broadcast new block to peers for synchronization
        for peer in self.peers:
            peer.synchronize_blockchain(self.blockchain)

    def synchronize_blockchain(self, new_chain):
        # Update the local chain if the received chain is longer and valid
        if len(new_chain.chain) > len(self.blockchain.chain) and new_chain.is_chain_valid():
            print(f"Node {self.node_id} synchronized its blockchain to match peer's longer chain.")
            self.blockchain = copy.deepcopy(new_chain)

    def perform_audit(self):
        # Use the ComplianceAuditToolkit to audit the blockchain
        self.audit_toolkit.audit(self.blockchain)

    def decrypt_transaction(self, encrypted_data):
        # Decrypt the transaction for reading or audit purposes
        try:
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None


# Updated test for enhanced synchronization and data security
if __name__ == "__main__":
    # Create enhanced blockchain nodes
    node_A = BlockchainNodeSecure("A", difficulty=2)
    node_B = BlockchainNodeSecure("B", difficulty=2)
    node_C = BlockchainNodeSecure("C", difficulty=2)

    # Establish peer connections
    node_A.add_peer(node_B)
    node_A.add_peer(node_C)
    node_B.add_peer(node_A)
    node_B.add_peer(node_C)
    node_C.add_peer(node_A)
    node_C.add_peer(node_B)

    # Generate some transactions
    transactions = [
        Transaction("Alice", "Bob", 10),
        Transaction("Charlie", "David", 20),
        Transaction("Eve", "Frank", 50)
    ]

    # Add user consent for some transactions in Transparency Suite
    node_A.transparency_suite.add_consent("Alice", "approved")
    node_A.transparency_suite.add_consent("Charlie", "approved")

    # Nodes receive and encrypt transactions
    for tx in transactions:
        node_A.receive_transaction(tx)
        time.sleep(0.5)

    # Nodes mine blocks
    node_A.mine_block()
    node_B.mine_block()  # B and C won't have transactions if A already mined the mempool

    # Final state of each blockchain (with synchronization)
    for node in [node_A, node_B, node_C]:
        print(f"\nFinal blockchain for Node {node.node_id}:")
        for block in node.blockchain.chain:
            print(f"  Block {block.index} [Hash: {block.hash}, Prev: {block.previous_hash}, Transactions: {len(block.transactions)}]")

            # Decrypt and display transactions
            for tx in block.transactions:
                decrypted_tx = node.decrypt_transaction(tx.encrypted_data)
                if decrypted_tx:
                    print(f"    Decrypted Transaction: {decrypted_tx}")
import numpy as np
from sklearn.ensemble import IsolationForest

# Adding Jetson Nano capabilities simulation: AI-based anomaly detection using Isolation Forest

class BlockchainNodeAI:
    def __init__(self, node_id, difficulty=2):
        self.node_id = node_id
        self.blockchain = Blockchain(difficulty=difficulty)
        self.geosovereign = GeoSovereign()
        self.regblock = RegBlock()
        self.transparency_suite = TransparencySuite()
        self.erasure_guard = ErasureGuard()
        self.audit_toolkit = ComplianceAuditToolkit()
        self.peers = []  # List of peer nodes
        self.isolation_forest_model = IsolationForest(contamination=0.1, random_state=42)
        self.transaction_data = []

    def add_peer(self, peer_node):
        self.peers.append(peer_node)

    def receive_transaction(self, transaction):
        # Encrypt transaction data at rest
        transaction_data = json.dumps(transaction.to_dict()).encode()
        encrypted_data = cipher_suite.encrypt(transaction_data)
        transaction.encrypted_data = encrypted_data

        # Determine geographic region for compliance
        region = self.geosovereign.detect_data_origin(transaction)
        # Apply regulatory compliance based on detected region
        self.regblock.apply_regulations(region)

        # Simulate AI-based anomaly detection on the transaction
        if not self.run_anomaly_detection(transaction):
            print(f"Transaction from {transaction.sender} to {transaction.receiver} flagged as anomalous and not added.")
            return  # Skip adding the anomalous transaction

        # Add encrypted transaction to the blockchain's mempool
        self.blockchain.add_transaction(transaction)

    def run_anomaly_detection(self, transaction):
        # Convert transaction to a numerical representation for AI processing
        # Here, we use a simple representation of sender, receiver, and amount
        sender_hash = hash(transaction.sender) % 100
        receiver_hash = hash(transaction.receiver) % 100
        transaction_amount = transaction.amount

        # Prepare transaction data for prediction
        transaction_feature = [sender_hash, receiver_hash, transaction_amount]
        self.transaction_data.append(transaction_feature)

        # Train the model with current data (in a real scenario, training would be offline and periodically)
        if len(self.transaction_data) > 10:  # Start anomaly detection after collecting some data
            np_transaction_data = np.array(self.transaction_data)
            self.isolation_forest_model.fit(np_transaction_data)

            # Predict if the current transaction is anomalous
            prediction = self.isolation_forest_model.predict([transaction_feature])
            return prediction[0] == 1  # Return True if not anomalous, False otherwise
        else:
            return True  # If not enough data, assume normal

    def mine_block(self):
        # Before mining, check all transactions for user consent via Transparency Suite
        for tx in self.blockchain.mempool:
            if tx.sender in self.transparency_suite.consent_registry:
                if self.transparency_suite.consent_registry[tx.sender] != "approved":
                    print(f"Transaction from {tx.sender} not approved for mining.")
                    self.blockchain.mempool.remove(tx)

        # Proceed with mining
        self.blockchain.mine_block()

        # Broadcast new block to peers for synchronization
        for peer in self.peers:
            peer.synchronize_blockchain(self.blockchain)

    def synchronize_blockchain(self, new_chain):
        # Update the local chain if the received chain is longer and valid
        if len(new_chain.chain) > len(self.blockchain.chain) and new_chain.is_chain_valid():
            print(f"Node {self.node_id} synchronized its blockchain to match peer's longer chain.")
            self.blockchain = copy.deepcopy(new_chain)

    def perform_audit(self):
        # Use the ComplianceAuditToolkit to audit the blockchain
        self.audit_toolkit.audit(self.blockchain)

    def decrypt_transaction(self, encrypted_data):
        # Decrypt the transaction for reading or audit purposes
        try:
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None


# Updated test for AI-enhanced blockchain node
if __name__ == "__main__":
    # Create AI-enhanced blockchain nodes
    node_A = BlockchainNodeAI("A", difficulty=2)
    node_B = BlockchainNodeAI("B", difficulty=2)
    node_C = BlockchainNodeAI("C", difficulty=2)

    # Establish peer connections
    node_A.add_peer(node_B)
    node_A.add_peer(node_C)
    node_B.add_peer(node_A)
    node_B.add_peer(node_C)
    node_C.add_peer(node_A)
    node_C.add_peer(node_B)

    # Generate some transactions
    transactions = [
        Transaction("Alice", "Bob", 10),
        Transaction("Charlie", "David", 2000),  # Anomalous transaction (high amount)
        Transaction("Eve", "Frank", 50),
        Transaction("Bob", "Eve", 5),
        Transaction("David", "Alice", 1000),  # Another potentially anomalous transaction
    ]

    # Add user consent for some transactions in Transparency Suite
    node_A.transparency_suite.add_consent("Alice", "approved")
    node_A.transparency_suite.add_consent("Charlie", "approved")

    # Nodes receive and verify transactions using AI-based anomaly detection
    for tx in transactions:
        node_A.receive_transaction(tx)
        time.sleep(0.5)

    # Nodes mine blocks
    node_A.mine_block()
    node_B.mine_block()  # B and C won't have transactions if A already mined the mempool

    # Final state of each blockchain (with synchronization)
    for node in [node_A, node_B, node_C]:
        print(f"\nFinal blockchain for Node {node.node_id}:")
        for block in node.blockchain.chain:
            print(f"  Block {block.index} [Hash: {block.hash}, Prev: {block.previous_hash}, Transactions: {len(block.transactions)}]")

            # Decrypt and display transactions
            for tx in block.transactions:
                decrypted_tx = node.decrypt_transaction(tx.encrypted_data)
                if decrypted_tx:
                    print(f"    Decrypted Transaction: {decrypted_tx}")
class BlockchainNodeMinerOptimized:
    """A Jetson Nano node that acts as a miner, decentralized storage, wallet, and explorer with optimized mining."""
    def __init__(self, node_id, difficulty=2):
        self.node_id = node_id
        self.blockchain = Blockchain(difficulty=difficulty)
        self.geosovereign = GeoSovereign()
        self.regblock = RegBlock()
        self.transparency_suite = TransparencySuite()
        self.erasure_guard = ErasureGuard()
        self.audit_toolkit = ComplianceAuditToolkit()
        self.peers = []  # List of peer nodes
        self.isolation_forest_model = IsolationForest(contamination=0.1, random_state=42)
        self.transaction_data = []
        self.storage = DecentralizedStorage(storage_path=f"{node_id}_storage")
        self.wallet_balance = 1000  # Each node has an initial balance for demo purposes
        self.mining = False

    def add_peer(self, peer_node):
        self.peers.append(peer_node)

    def receive_transaction(self, transaction):
        # Encrypt transaction data at rest
        transaction_data = json.dumps(transaction.to_dict()).encode()
        encrypted_data = cipher_suite.encrypt(transaction_data)
        transaction.encrypted_data = encrypted_data

        # Determine geographic region for compliance
        region = self.geosovereign.detect_data_origin(transaction)
        # Apply regulatory compliance based on detected region
        self.regblock.apply_regulations(region)

        # AI-based anomaly detection on the transaction
        if not self.run_anomaly_detection(transaction):
            print(f"Transaction from {transaction.sender} to {transaction.receiver} flagged as anomalous and not added.")
            return

        # Add encrypted transaction to the blockchain's mempool
        self.blockchain.add_transaction(transaction)

        # Store the encrypted transaction in decentralized storage
        data_id = hashlib.sha256(transaction_data).hexdigest()
        self.storage.store_data(transaction.to_dict(), data_id)

        # If not mining, start mining
        if not self.mining:
            mining_thread = threading.Thread(target=self.mine_block)
            mining_thread.start()

    def run_anomaly_detection(self, transaction):
        # Convert transaction to a numerical representation for AI processing
        sender_hash = hash(transaction.sender) % 100
        receiver_hash = hash(transaction.receiver) % 100
        transaction_amount = transaction.amount

        # Prepare transaction data for prediction
        transaction_feature = [sender_hash, receiver_hash, transaction_amount]
        self.transaction_data.append(transaction_feature)

        # Train the model with current data
        if len(self.transaction_data) > 10:
            np_transaction_data = np.array(self.transaction_data)
            self.isolation_forest_model.fit(np_transaction_data)

            # Predict if the current transaction is anomalous
            prediction = self.isolation_forest_model.predict([transaction_feature])
            return prediction[0] == 1
        else:
            return True

    def mine_block(self):
        self.mining = True
        while True:
            # Before mining, check all transactions for user consent via Transparency Suite
            for tx in list(self.blockchain.mempool):  # Use a copy to avoid modification issues during iteration
                if tx.sender in self.transparency_suite.consent_registry:
                    if self.transparency_suite.consent_registry[tx.sender] != "approved":
                        print(f"Transaction from {tx.sender} not approved for mining.")
                        self.blockchain.mempool.remove(tx)

            # Proceed with mining if there are transactions in the mempool
            if self.blockchain.mempool:
                self.blockchain.mine_block()

                # Broadcast the new block to peers for synchronization
                for peer in self.peers:
                    peer.synchronize_blockchain(self.blockchain)
                
                break  # Stop mining loop after a successful block creation
            else:
                # Stop mining if no transactions are left to mine
                print(f"Node {self.node_id} found no transactions to mine. Pausing mining.")
                break

        self.mining = False

    def synchronize_blockchain(self, new_chain):
        if len(new_chain.chain) > len(self.blockchain.chain) and new_chain.is_chain_valid():
            print(f"Node {self.node_id} synchronized its blockchain to match peer's longer chain.")
            self.blockchain = copy.deepcopy(new_chain)

    def perform_audit(self):
        self.audit_toolkit.audit(self.blockchain)

    def decrypt_transaction(self, encrypted_data):
        try:
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None


# Updated test for distributed mining with optimized mining control
if __name__ == "__main__":
    # Create Jetson Nano nodes acting as miners
    node_A = BlockchainNodeMinerOptimized("A", difficulty=2)
    node_B = BlockchainNodeMinerOptimized("B", difficulty=2)
    node_C = BlockchainNodeMinerOptimized("C", difficulty=2)

    # Establish peer connections
    node_A.add_peer(node_B)
    node_A.add_peer(node_C)
    node_B.add_peer(node_A)
    node_B.add_peer(node_C)
    node_C.add_peer(node_A)
    node_C.add_peer(node_B)

    # Generate some transactions
    transactions = [
        Transaction("Alice", "Bob", 10),
        Transaction("Charlie", "David", 200),
        Transaction("Eve", "Frank", 50),
    ]

    # Add user consent for some transactions in Transparency Suite
    node_A.transparency_suite.add_consent("Alice", "approved")
    node_A.transparency_suite.add_consent("Charlie", "approved")

    # Nodes receive and verify transactions
    for tx in transactions:
        node_A.receive_transaction(tx)
        node_B.receive_transaction(tx)
        node_C.receive_transaction(tx)
        time.sleep(0.5)

    # Allow time for mining to complete
    time.sleep(10)

    # Final state of each blockchain (with synchronization)
    for node in [node_A, node_B, node_C]:
        print(f"\nFinal blockchain for Node {node.node_id}:")
        for block in node.blockchain.chain:
            print(f"  Block {block.index} [Hash: {block.hash}, Prev: {block.previous_hash}, Transactions: {len(block.transactions)}]")

            # Decrypt and display transactions
            for tx in block.transactions:
                decrypted_tx = node.decrypt_transaction(tx.encrypted_data)
                if decrypted_tx:
                    print(f"    Decrypted Transaction: {decrypted_tx}")
