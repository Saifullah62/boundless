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

# Utility Functions

def establish_connection(peer, cafile="trusted-certs.pem"):
    """
    Establishes a secure SSL connection to a peer.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=cafile)
    try:
        with socket.create_connection((peer.split(':')[0], int(peer.split(':')[1])), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=peer) as s:
                return s
    except (socket.error, ssl.SSLError) as e:
        logging.error(f"Failed to connect to {peer}: {e}")
        return None

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

        # Start peer synchronization and discovery threads
        self.thread_manager = ThreadManager()
        self.thread_manager.start_thread(PeerSyncThread, self.peers, self.peer_lock, self.connect_to_blockchain)
        self.thread_manager.start_thread(PeerDiscoveryThread, self.peers, self.peer_lock, self.request_peers_from_peer)

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

    # Peer Interaction Methods
    def request_peers_from_peer(self, peer):
        """
        Connects to a peer and requests their known peers to expand the peer list.
        """
        connection = establish_connection(peer)
        if connection:
            try:
                connection.sendall(f"REQUEST_PEER_LIST|{ACCESS_TOKEN}".encode())
                data = connection.recv(BUFFER_SIZE).decode()
                received_peers = data.split(',')
                for new_peer in received_peers:
                    if new_peer not in self.peers and new_peer != peer:
                        logging.info(f"Discovered new peer: {new_peer}")
                        self.peers.add(new_peer)
            except Exception as e:
                logging.error(f"Failed to request peers from {peer}: {e}")

    def connect_to_blockchain(self, host):
        """
        Connect to a peer's blockchain and sync if their chain is longer.
        """
        connection = establish_connection(host)
        if connection:
            try:
                connection.sendall(f"REQUEST_BLOCKCHAIN|{ACCESS_TOKEN}".encode())
                data = b""
                while True:
                    part = connection.recv(BUFFER_SIZE)
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
            except json.JSONDecodeError as e:
                logging.error(f"Failed to decode blockchain JSON data from {host}: {e}")
            except Exception as e:
                logging.error(f"Unexpected error while connecting to blockchain: {e}")

    # Blockchain Validation
    def is_valid_chain(self, chain):
        """
        Validates the entire blockchain by verifying hashes, previous hashes, and transaction signatures.
        """
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

        logging.info("Chain validated successfully.")
        return True

    # Blockchain Persistence
    def save_chain(self):
        """
        Saves the blockchain to a JSON file to ensure persistence.
        """
        try:
            with open(self.filename, "w") as f:
                json.dump([self.block_to_dict(block) for block in self.chain], f, indent=4)
            logging.info("Blockchain saved successfully.")
        except (IOError, Exception) as e:
            logging.error(f"Failed to save blockchain to file: {e}")

    def load_chain(self):
        """
        Loads the blockchain from a JSON file if it exists.
        """
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

# Thread Management
class ThreadManager:
    def __init__(self):
        self.threads = []

    def start_thread(self, thread_class, *args, **kwargs):
        thread = thread_class(*args, **kwargs)
        thread.start()
        self.threads.append(thread)
        logging.info(f"Started thread: {thread_class.__name__}")

    def stop_all_threads(self):
        for thread in self.threads:
            thread.stop()
        logging.info("All threads stopped.")

# Peer Synchronization Thread
class PeerSyncThread(threading.Thread):
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
        self.stop_event.set()

# Peer Discovery Thread
class PeerDiscoveryThread(threading.Thread):
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
        self.stop_event.set()
# Rate Limiter for Preventing Abuse
class RateLimiter:
    RATE_LIMIT_WINDOW = timedelta(seconds=10)
    MAX_REQUESTS_PER_WINDOW = 5

    def __init__(self):
        self.rate_limit_tracker = defaultdict(lambda: defaultdict(list))

    def is_rate_limited(self, ip, command):
        """
        Checks if the specified IP address has exceeded the maximum number of requests for a given command
        within the defined rate limit window.
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

# Peer Synchronization Thread
class PeerSyncThread(threading.Thread):
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
            connection = establish_connection(peer)
            if connection:
                connection.sendall(f"REQUEST_PEER_LIST|{ACCESS_TOKEN}".encode())
                data = connection.recv(BUFFER_SIZE).decode()
                received_peers = data.split(',')
                for new_peer in received_peers:
                    if new_peer not in self.peers and new_peer != peer:
                        logging.info(f"Discovered new peer: {new_peer}")
                        self.peers.add(new_peer)
        except (socket.error, ssl.SSLError) as e:
            logging.error(f"Failed to request peers from {peer}: {e}")

    def connect_to_blockchain(self, host):
        """
        Connect to a peer's blockchain and sync if their chain is longer.
        """
        try:
            connection = establish_connection(host)
            if connection:
                connection.sendall(f"REQUEST_BLOCKCHAIN|{ACCESS_TOKEN}".encode())
                data = b""
                while True:
                    part = connection.recv(BUFFER_SIZE)
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
        except json.JSONDecodeError as e:
            logging.error(f"Failed to decode blockchain JSON data from {host}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error while connecting to blockchain: {e}")

    def create_genesis_block(self):
        """
        Creates the first block in the blockchain.
        """
        return Block(0, "0", [], nonce=0)

    def dict_to_block(self, block_dict):
        """
        Converts a dictionary representation back to a block.
        """
        transactions = [Transaction(**tx) for tx in block_dict["transactions"]]
        block = Block(block_dict["index"], block_dict["previous_hash"], transactions,
                      block_dict["timestamp"], block_dict["nonce"])
        block.hash = block_dict["hash"]
        block.difficulty = block_dict.get("difficulty", 0)
        return block

    def block_to_dict(self, block):
        """
        Converts a block to a dictionary representation.
        """
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
        """
        Validates the entire blockchain by verifying hashes, previous hashes, and transaction signatures.
        """
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
        """
        Deserializes a public key from PEM format.
        """
        try:
            return serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        except ValueError as e:
            logging.error(f"Failed to load public key: {e}")
            raise

    def cleanup_mempool(self):
        """
        Cleans up the mempool by removing invalid or expired transactions.
        """
        current_time = time.time()
        valid_transactions = []

        for _, _, transaction in self.mempool:
            # Check if the transaction is still valid (e.g., timestamp is within acceptable range)
            if transaction.timestamp > current_time - 3600:  # 1-hour validity
                valid_transactions.append((_, _, transaction))

        self.mempool = valid_transactions  # Update mempool with valid transactions

    def save_chain(self):
        """
        Saves the blockchain to a JSON file.
        """
        try:
            with open(self.filename, "w") as f:
                json.dump([self.block_to_dict(block) for block in self.chain], f, indent=4)
            logging.info("Blockchain saved successfully.")
        except (IOError, Exception) as e:
            logging.error(f"Failed to save blockchain to file: {e}")

    def save_chain(self):
        """
        Saves the blockchain to a JSON file, ensuring that the entire chain is persisted for future use.
        """
        try:
            with open(self.filename, "w") as f:
                json.dump([self.block_to_dict(block) for block in self.chain], f, indent=4)
            logging.info("Blockchain saved successfully.")
        except (IOError, Exception) as e:
            logging.error(f"Failed to save blockchain to file: {e}")

    def load_chain(self):
        """
        Loads the blockchain from a JSON file if it exists, ensuring continuity of the blockchain's state.
        """
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

    def sync_with_peer(self, peer):
        """
        Attempts to synchronize with a peer by fetching their blockchain and checking if it is longer.
        """
        try:
            connection = establish_connection(peer)
            if connection:
                connection.sendall(f"REQUEST_BLOCKCHAIN|{ACCESS_TOKEN}".encode())
                data = b""
                while True:
                    part = connection.recv(BUFFER_SIZE)
                    if not part:
                        break
                    data += part
                received_chain = json.loads(data.decode())
                received_chain_objects = [self.dict_to_block(block) for block in received_chain]

                if self.is_valid_chain(received_chain_objects) and len(received_chain_objects) > len(self.chain):
                    self.chain = received_chain_objects
                    self.save_chain()
                    logging.info("Blockchain synchronized with peer's chain.")
                else:
                    logging.info("Peer's blockchain is not valid or shorter. No update performed.")
        except json.JSONDecodeError as e:
            logging.error(f"Failed to decode blockchain JSON data from peer {peer}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error during synchronization with peer: {e}")

    def add_block(self, block):
        """
        Adds a new block to the chain after validating its hash and other parameters.
        """
        if block.previous_hash == self.get_latest_block().hash and block.hash == block.calculate_hash():
            self.chain.append(block)
            self.save_chain()
            logging.info(f"Block {block.index} added to the blockchain.")
        else:
            logging.error(f"Failed to add block {block.index}: invalid block data.")

    def get_latest_block(self):
        """
        Returns the latest block in the chain.
        """
        return self.chain[-1]

    def mine_block(self, transactions):
        """
        Mines a new block using the given transactions.
        """
        latest_block = self.get_latest_block()
        new_block = Block(index=latest_block.index + 1, previous_hash=latest_block.hash, transactions=transactions)
        new_block.mine_block(self.difficulty)
        self.add_block(new_block)

    def add_transaction(self, transaction):
        """
        Adds a transaction to the mempool after verifying its validity.
        """
        if transaction.verify_signature(self.get_public_key(transaction.sender)) and transaction.amount > 0:
            heapq.heappush(self.mempool, (-transaction.fee, time.time(), transaction))
            logging.info(f"Transaction added to mempool: {transaction}")
        else:
            logging.warning(f"Invalid transaction attempted: {transaction}")

    def mine_new_block(self):
        """
        Mines a new block using transactions from the mempool.
        """
        if len(self.mempool) == 0:
            logging.info("No transactions in mempool to mine.")
            return

        selected_transactions = []
        while len(selected_transactions) < 10 and self.mempool:
            _, _, transaction = heapq.heappop(self.mempool)
            selected_transactions.append(transaction)

        self.mine_block(selected_transactions)
        logging.info("New block mined with transactions from mempool.")

def validate_and_add_block(self, block):
        """
        Validates a new block and adds it to the blockchain if valid.
        This method checks the block's hash and its previous hash to ensure integrity.
        """
        if self.is_valid_new_block(block, self.get_latest_block()):
            self.chain.append(block)
            self.save_chain()
            logging.info(f"Block {block.index} successfully validated and added.")
        else:
            logging.error(f"Invalid block {block.index}: could not be added.")

    def is_valid_new_block(self, new_block, previous_block):
        """
        Validates a new block by comparing its hash and previous hash with the current blockchain.
        """
        if new_block.previous_hash != previous_block.hash:
            logging.error(f"Invalid block: Previous hash does not match. Block index: {new_block.index}")
            return False
        if new_block.hash != new_block.calculate_hash():
            logging.error(f"Invalid block: Hash does not match calculated hash. Block index: {new_block.index}")
            return False
        return True

    def add_transaction(self, transaction):
        """
        Adds a transaction to the mempool after verifying its validity.
        """
        if self.verify_transaction(transaction):
            heapq.heappush(self.mempool, (-transaction.fee, time.time(), transaction))
            logging.info(f"Transaction added to mempool: {transaction}")
        else:
            logging.warning(f"Invalid transaction attempted: {transaction}")

    def verify_transaction(self, transaction):
        """
        Verifies if a transaction is valid based on the sender's balance, signature, and other constraints.
        """
        sender_balance = self.balances.get(transaction.sender, 0)

        # Check if the transaction already exists in the chain to prevent double-spending
        if self.is_transaction_in_chain(transaction):
            logging.warning(f"Transaction from {transaction.sender} to {transaction.receiver} already exists.")
            return False

        if sender_balance >= transaction.amount + transaction.fee and transaction.verify_signature(self.get_public_key(transaction.sender)):
            return True
        else:
            logging.warning(f"Transaction from {transaction.sender} to {transaction.receiver} is invalid due to insufficient balance or invalid signature.")
            return False

    def is_transaction_in_chain(self, transaction):
        """
        Checks if a transaction is already included in the blockchain to prevent double-spending.
        """
        for block in self.chain:
            if any(tx == transaction for tx in block.transactions):
                return True
        return False

    def mine_new_block(self):
        """
        Mines a new block using transactions from the mempool.
        """
        if not self.mempool:
            logging.info("No transactions in mempool to mine.")
            return

        selected_transactions = self.select_transactions_for_block()
        new_block = Block(
            index=len(self.chain), 
            previous_hash=self.get_latest_block().hash, 
            transactions=selected_transactions
        )
        new_block.mine_block(self.difficulty)
        self.add_block(new_block)

    def select_transactions_for_block(self, max_transactions=10):
        """
        Selects transactions from the mempool for inclusion in a new block.
        """
        selected_transactions = []
        while len(selected_transactions) < max_transactions and self.mempool:
            _, _, transaction = heapq.heappop(self.mempool)
            selected_transactions.append(transaction)

            # Update balances
            self.update_balances(transaction)
        return selected_transactions

    def update_balances(self, transaction):
        """
        Updates the sender and receiver balances after a transaction.
        """
        self.balances[transaction.sender] -= (transaction.amount + transaction.fee)
        self.balances[transaction.receiver] = self.balances.get(transaction.receiver, 0) + transaction.amount

    def adjust_difficulty(self):
        """
        Adjusts the mining difficulty based on the average mining time of the last set of blocks.
        """
        if len(self.block_times) >= 10:
            avg_mining_duration = sum(self.block_times[-10:]) / 10
            target_duration = 180  # Target block time in seconds
            if avg_mining_duration < target_duration * 0.9:
                self.difficulty += 1
            elif avg_mining_duration > target_duration * 1.1:
                self.difficulty = max(1, self.difficulty - 1)

            logging.info(f"Adjusted mining difficulty to {self.difficulty}.")

    def sync_with_peer(self, peer):
        """
        Attempts to synchronize with a peer by fetching their blockchain and checking if it is longer.
        """
        try:
            connection = self.connect_to_peer(peer)
            if connection:
                connection.sendall(f"REQUEST_BLOCKCHAIN|{ACCESS_TOKEN}".encode())
                data = b""
                while True:
                    part = connection.recv(BUFFER_SIZE)
                    if not part:
                        break
                    data += part
                received_chain = json.loads(data.decode())
                received_chain_objects = [self.dict_to_block(block) for block in received_chain]

                if self.is_valid_chain(received_chain_objects) and len(received_chain_objects) > len(self.chain):
                    self.chain = received_chain_objects
                    self.save_chain()
                    logging.info("Blockchain synchronized with peer's chain.")
                else:
                    logging.info("Peer's blockchain is not valid or shorter. No update performed.")
        except json.JSONDecodeError as e:
            logging.error(f"Failed to decode blockchain JSON data from peer {peer}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error during synchronization with peer: {e}")

    # Thread-safe method to add new peers
    def add_peer(self, peer):
        """
        Adds a peer to the peer set, ensuring no duplicate entries.
        """
        with self.peer_lock:
            if peer not in self.peers:
                self.peers.add(peer)
                logging.info(f"Peer {peer} added successfully.")

    def connect_to_peer(self, peer):
        """
        Establishes a connection to a given peer and returns the socket.
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((peer.split(':')[0], int(peer.split(':')[1])), timeout=10) as sock:
                return context.wrap_socket(sock, server_hostname=peer)
        except (socket.error, ssl.SSLError) as e:
            logging.error(f"Failed to connect to peer {peer}: {e}")
            return None

    def stop_peer_threads(self):
        """
        Stops the peer synchronization and discovery threads gracefully.
        """
        self.peer_discovery_thread.stop()
        self.peer_sync_thread.stop()
        logging.info("Peer threads stopped successfully.")

def cleanup_mempool(self):
        """
        Cleans up the mempool by removing invalid or expired transactions.
        This method ensures that the mempool contains only valid transactions within a specified validity period.
        """
        current_time = time.time()
        valid_transactions = []

        # Remove transactions that are expired or invalid
        for _, _, transaction in self.mempool:
            if transaction.timestamp > current_time - 3600:  # Only keep transactions within 1-hour validity
                valid_transactions.append((_, _, transaction))

        self.mempool = valid_transactions  # Update mempool with valid transactions
        logging.info("Mempool cleaned up, expired transactions removed.")

    def reconcile_balances(self):
        """
        Reconciles the balances of all accounts by iterating through the entire blockchain.
        This method is used to rebuild the balance sheet from scratch based on the transactions.
        """
        self.balances = defaultdict(int)  # Reset all balances

        for block in self.chain:
            for transaction in block.transactions:
                self.balances[transaction.sender] -= (transaction.amount + transaction.fee)
                self.balances[transaction.receiver] += transaction.amount

        logging.info("Balances reconciled based on the blockchain.")

    def prune_chain(self, retain_last_n=100):
        """
        Prunes the blockchain by keeping only the last N blocks.
        This method is useful to reduce the storage requirements of the blockchain, assuming older data is checkpointed.
        """
        if len(self.chain) > retain_last_n:
            self.chain = self.chain[-retain_last_n:]
            self.save_chain()
            logging.info(f"Blockchain pruned to the last {retain_last_n} blocks.")

    def broadcast_block(self, block):
        """
        Broadcasts a newly mined block to all peers.
        This method ensures that all connected peers are informed of new blocks.
        """
        for peer in list(self.peers):
            try:
                connection = self.connect_to_peer(peer)
                if connection:
                    connection.sendall(f"NEW_BLOCK|{json.dumps(self.block_to_dict(block))}|{ACCESS_TOKEN}".encode())
                    logging.info(f"Broadcasted new block {block.index} to peer {peer}.")
            except Exception as e:
                logging.error(f"Failed to broadcast block to peer {peer}: {e}")

    def validate_blockchain(self):
        """
        Validates the entire blockchain.
        Checks each block's hash, previous hash, and the validity of all contained transactions.
        """
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if not self.is_valid_new_block(current_block, previous_block):
                logging.error(f"Blockchain validation failed at block {current_block.index}.")
                return False

        logging.info("Blockchain validated successfully.")
        return True

    def initiate_peer_sync(self):
        """
        Starts the peer synchronization and peer discovery threads.
        This method initiates the peer discovery and blockchain sync process across the network.
        """
        self.peer_discovery_thread = PeerDiscoveryThread(self.peers, self.peer_lock, self.request_peers_from_peer)
        self.peer_sync_thread = PeerSyncThread(self.peers, self.peer_lock, self.connect_to_blockchain)
        self.peer_discovery_thread.start()
        self.peer_sync_thread.start()
        logging.info("Peer synchronization and discovery threads initiated.")

         def stop_all_threads(self):
        """
        Stops all running threads related to peer synchronization and discovery.
        Ensures all peer-related threads are gracefully stopped to avoid data corruption or inconsistencies.
        """
        threads = [
            ('peer_discovery_thread', self.peer_discovery_thread),
            ('peer_sync_thread', self.peer_sync_thread)
        ]

        for thread_name, thread in threads:
            if hasattr(self, thread_name) and thread and thread.is_alive():
                thread.stop()
                logging.info(f"{thread_name} has been stopped successfully.")

        logging.info("All peer-related threads have been stopped.")

    def handle_peer_request(self, ip, command):
        """
        Handles requests from peers, enforcing rate limits to prevent abuse.
        Verifies if the rate limit is exceeded before executing the requested command.
        """
        if self.rate_limiter.is_rate_limited(ip, command):
            logging.warning(f"Rate limit exceeded for IP {ip} on command {command}.")
            return "RATE_LIMIT_EXCEEDED"

        # Handle the command normally (e.g., sync, request block, etc.)
        logging.info(f"Handled peer request from {ip}: {command}")
        return "COMMAND_HANDLED"

    def get_peer_list(self):
        """
        Returns a list of known peers to share with requesting nodes.
        Ensures thread-safe access to the peer list for consistency.
        """
        with self.peer_lock:
            logging.info("Providing peer list to requester.")
            return list(self.peers)

    def request_peers_from_peer(self, peer):
        """
        Requests known peers from another peer to enhance network connectivity.
        Uses a secure connection to request a peer list, adding new peers to the network.
        """
        try:
            connection = self.connect_to_peer(peer)
            if connection:
                connection.sendall(f"REQUEST_PEER_LIST|{ACCESS_TOKEN}".encode())
                data = connection.recv(BUFFER_SIZE).decode()
                received_peers = data.split(',')
                with self.peer_lock:
                    for new_peer in received_peers:
                        if new_peer and new_peer not in self.peers and new_peer != peer:
                            self.add_peer(new_peer)
                            logging.info(f"Discovered new peer: {new_peer}")
        except (socket.error, ssl.SSLError) as e:
            logging.error(f"Failed to request peers from {peer}: {e}")

    def initialize_rate_limiter(self):
        """
        Initializes the rate limiter to handle requests from peers.
        This prevents abuse by limiting the number of requests that can be made in a given timeframe.
        """
        self.rate_limiter = RateLimiter()
        logging.info("Rate limiter initialized and ready to manage peer requests.")

    def connect_to_blockchain(self, host):
        """
        Connects to a peer's blockchain and syncs if their chain is longer.
        Attempts to establish a connection with a peer, request their chain, and replace the local chain if appropriate.
        """
        try:
            connection = self.connect_to_peer(host)
            if connection:
                connection.sendall(f"REQUEST_BLOCKCHAIN|{ACCESS_TOKEN}".encode())
                data = b""
                while True:
                    part = connection.recv(BUFFER_SIZE)
                    if not part:
                        break
                    data += part
                received_chain = json.loads(data.decode())
                received_chain_objects = [self.dict_to_block(block) for block in received_chain]

                if self.is_valid_chain(received_chain_objects) and len(received_chain_objects) > len(self.chain):
                    self.chain = received_chain_objects
                    self.save_chain()
                    logging.info("Replaced current blockchain with the longer valid chain from peer.")
                else:
                    logging.info("Received blockchain from peer is invalid or not longer. No update performed.")
        except (socket.error, ssl.SSLError, json.JSONDecodeError) as e:
            logging.error(f"Error during blockchain synchronization from host {host}: {e}")

    def cleanup_mempool(self):
        """
        Cleans up the mempool by removing invalid or expired transactions.
        This method ensures that the mempool contains only valid transactions within a specified validity period.
        """
        current_time = time.time()
        valid_transactions = []

        # Remove transactions that are expired or invalid
        for _, _, transaction in self.mempool:
            if transaction.timestamp > current_time - 3600:  # Only keep transactions within 1-hour validity
                valid_transactions.append((_, _, transaction))

        self.mempool = valid_transactions  # Update mempool with valid transactions
        logging.info("Mempool cleaned up, expired transactions removed.")

    def reconcile_balances(self):
        """
        Reconciles the balances of all accounts by iterating through the entire blockchain.
        This method is used to rebuild the balance sheet from scratch based on the transactions.
        """
        self.balances = defaultdict(int)  # Reset all balances

        for block in self.chain:
            for transaction in block.transactions:
                self.balances[transaction.sender] -= (transaction.amount + transaction.fee)
                self.balances[transaction.receiver] += transaction.amount

        logging.info("Balances reconciled based on the blockchain.")

    def prune_chain(self, retain_last_n=100):
        """
        Prunes the blockchain by keeping only the last N blocks.
        This method is useful to reduce the storage requirements of the blockchain, assuming older data is checkpointed.
        """
        if len(self.chain) > retain_last_n:
            self.chain = self.chain[-retain_last_n:]
            self.save_chain()
            logging.info(f"Blockchain pruned to the last {retain_last_n} blocks.")

    def broadcast_block(self, block):
        """
        Broadcasts a newly mined block to all peers.
        This method ensures that all connected peers are informed of new blocks.
        """
        for peer in list(self.peers):
            try:
                connection = self.connect_to_peer(peer)
                if connection:
                    connection.sendall(f"NEW_BLOCK|{json.dumps(self.block_to_dict(block))}|{ACCESS_TOKEN}".encode())
                    logging.info(f"Broadcasted new block {block.index} to peer {peer}.")
            except Exception as e:
                logging.error(f"Failed to broadcast block to peer {peer}: {e}")

    def validate_blockchain(self):
        """
        Validates the entire blockchain.
        Checks each block's hash, previous hash, and the validity of all contained transactions.
        """
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if not self.is_valid_new_block(current_block, previous_block):
                logging.error(f"Blockchain validation failed at block {current_block.index}.")
                return False

        logging.info("Blockchain validated successfully.")
        return True

    def initiate_peer_sync(self):
        """
        Initiates and manages the peer synchronization and discovery processes in a streamlined way.
        Starts both peer discovery and blockchain sync threads, ensuring robust network connectivity.
        Ensures that only one instance of each thread is running.
        """
        # Ensure proper thread initialization with enhanced consistency and error handling
        try:
            # Start peer discovery thread if not already running
            if not hasattr(self, 'peer_discovery_thread') or not self.peer_discovery_thread.is_alive():
                self.peer_discovery_thread = PeerDiscoveryThread(self.peers, self.peer_lock, self.request_peers_from_peer)
                self.peer_discovery_thread.start()
                logging.info("Peer discovery thread started.")
            else:
                logging.info("Peer discovery thread is already running.")

            # Start peer synchronization thread if not already running
            if not hasattr(self, 'peer_sync_thread') or not self.peer_sync_thread.is_alive():
                self.peer_sync_thread = PeerSyncThread(self.peers, self.peer_lock, self.connect_to_blockchain)
                self.peer_sync_thread.start()
                logging.info("Peer synchronization thread started.")
            else:
                logging.info("Peer synchronization thread is already running.")

            logging.info("Peer synchronization and discovery processes initiated successfully.")
        except Exception as e:
            logging.error(f"Failed to start peer synchronization threads: {e}")

    def connect_to_peer(self, peer):
        """
        Establishes a secure connection to a peer.
        Abstracts the logic for SSL socket connection, ensuring code reuse and consistency.
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((peer.split(':')[0], int(peer.split(':')[1])), timeout=10) as sock:
                logging.info(f"Successfully connected to peer {peer}.")
                return context.wrap_socket(sock, server_hostname=peer)
        except (socket.error, ssl.SSLError) as e:
            logging.error(f"Failed to connect to peer {peer}: {e}")
            return None

class Transaction:
    def __init__(self, sender, receiver, amount, fee, signature):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.fee = fee
        self.timestamp = time.time()
        self.signature = signature

    def to_dict(self):
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "fee": self.fee,
            "timestamp": self.timestamp,
            "signature": self.signature
        }

    def verify_signature(self, public_key):
        # Code to verify the transaction signature using the sender's public key.
        pass

class Block:
    def __init__(self, index, previous_hash, transactions, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.timestamp = time.time()
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def mine_block(self, difficulty):
        # Proof-of-work algorithm to find a valid nonce
        target = '0' * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()

def create_socket(peer):
    try:
        if ':' in peer:  # IPv6 address detected
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:  # IPv4 address
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return sock
    except socket.error as e:
        logging.error(f"Error creating socket for {peer}: {e}")
        return None
