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
rate_limit_tracker = defaultdict(list)

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
                        if not rate_limit_check(address[0]):
                            logging.warning(f"Rate limit exceeded for {address[0]}")
                            client_socket.sendall(b"RATE_LIMIT_EXCEEDED")
                            continue

                        request = client_socket.recv(BUFFER_SIZE).decode()
                        request_parts = request.split("|")

                        if len(request_parts) == 2 and request_parts[0] == "REQUEST_BLOCKCHAIN" and request_parts[1] == ACCESS_TOKEN:
                            blockchain_data = json.dumps([blockchain.block_to_dict(block) for block in blockchain.chain])
                            client_socket.sendall(blockchain_data.encode())
                            logging.info(f"Sent blockchain to peer at {address}")
                        else:
                            logging.warning(f"Unauthorized access attempt from {address}")
                            client_socket.sendall(b"ACCESS_DENIED")
                except Exception as e:
                    logging.error(f"Error handling client connection: {e}")


def rate_limit_check(ip):
    """Check if the given IP address exceeds the rate limit."""
    current_time = datetime.now()
    request_times = rate_limit_tracker[ip]
    # Remove outdated requests
    rate_limit_tracker[ip] = [t for t in request_times if current_time - t < RATE_LIMIT_WINDOW]
    # Check current rate
    if len(rate_limit_tracker[ip]) >= MAX_REQUESTS_PER_WINDOW:
        return False
    # Log new request
    rate_limit_tracker[ip].append(current_time)
    return True
# Third-party imports
from argon2 import PasswordHasher  # Add this import

# Initialize an Argon2 Password Hasher
argon_hasher = PasswordHasher()

class MerkleTree:
    """Constructs a Merkle Tree from a list of transactions."""
    def __init__(self, transactions):
        self.transactions = transactions
        self.root = self.build_tree([self.hash_data(str(tx)) for tx in transactions])

    @staticmethod
    def hash_data(data):
        """Hashes the given data using Argon2."""
        salt = os.urandom(16)  # Salt generation for each hash
        return argon_hasher.hash(salt + data.encode())  # Hash using Argon2

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
def start_server(blockchain):
    """Starts a server to listen for blockchain requests from peers with mutual TLS."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    context.load_verify_locations(cafile="client_ca.crt")  # Client CA
    context.verify_mode = ssl.CERT_REQUIRED  # Require client certificate

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("0.0.0.0", PORT))
        server.listen(5)
        with context.wrap_socket(server, server_side=True) as tls_server:
            logging.info(f"Blockchain server listening on port {PORT} with mutual TLS")

            while True:
                try:
                    client_socket, address = tls_server.accept()
                    with client_socket:
                        if not rate_limit_check(address[0]):
                            logging.warning(f"Rate limit exceeded for {address[0]}")
                            client_socket.sendall(b"RATE_LIMIT_EXCEEDED")
                            continue

                        request = client_socket.recv(BUFFER_SIZE).decode()
                        request_parts = request.split("|")

                        if len(request_parts) == 2 and request_parts[0] == "REQUEST_BLOCKCHAIN" and request_parts[1] == ACCESS_TOKEN:
                            blockchain_data = json.dumps([blockchain.block_to_dict(block) for block in blockchain.chain])
                            client_socket.sendall(blockchain_data.encode())
                            logging.info(f"Sent blockchain to peer at {address}")
                        else:
                            logging.warning(f"Unauthorized access attempt from {address}")
                            client_socket.sendall(b"ACCESS_DENIED")
                except Exception as e:
                    logging.error(f"Error handling client connection: {e}")
def connect_to_blockchain(self, host):
    """Connect to a peer's blockchain with mutual TLS."""
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_cert_chain(certfile="client.crt", keyfile="client.key")  # Client cert and key
        context.load_verify_locations(cafile="server_ca.crt")  # Server CA
        context.check_hostname = True  # Validate the server hostname
        context.verify_mode = ssl.CERT_REQUIRED  # Require server certificate verification

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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Encrypting a private key
def encrypt_private_key(private_key_pem, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(private_key_pem.encode()) + padder.finalize()
    encrypted_key = encryptor.update(padded_data) + encryptor.finalize()

    return salt + iv + encrypted_key

# Decrypting the private key
def decrypt_private_key(encrypted_data, password):
    salt, iv, encrypted_key = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_key = decryptor.update(encrypted_key) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    private_key_pem = unpadder.update(decrypted_padded_key) + unpadder.finalize()

    return private_key_pem.decode()
class Transaction:
    """Represents a transaction in the blockchain."""
    def __init__(self, sender, receiver, amount, private_key=None):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.signature = None
        self.transaction_hash = self.compute_hash()
        if private_key:
            self.sign_transaction(private_key)

    def compute_hash(self):
        """Computes the hash of the transaction for efficient storage."""
        transaction_data = f"{self.sender}{self.receiver}{self.amount}".encode()
        return hashlib.sha256(transaction_data).hexdigest()

    def to_dict(self):
        """Converts the transaction to a dictionary representation."""
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "signature": self.signature.hex() if self.signature else None,
            "transaction_hash": self.transaction_hash
        }
class MerkleTree:
    """Constructs a Merkle Tree from a list of precomputed transaction hashes."""
    def __init__(self, transaction_hashes):
        self.transaction_hashes = transaction_hashes
        self.root = self.build_tree(transaction_hashes)

    def build_tree(self, leaves):
        """Builds the Merkle Tree iteratively from the leaves (transaction hashes)."""
        while len(leaves) > 1:
            # If odd number of leaves, duplicate the last leaf
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1])
            # Create parent layer by hashing pairs of leaves
            parent_layer = [hashlib.sha256((leaves[i] + leaves[i + 1]).encode()).hexdigest() 
                            for i in range(0, len(leaves), 2)]
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
        self.transaction_hashes = [tx.compute_hash() for tx in transactions]  # Precomputed hashes
        self.merkle_root = MerkleTree(self.transaction_hashes).root
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Calculates the SHA-512 hash of the block."""
        block_string = f"{self.index}{self.previous_hash}{self.merkle_root}{self.timestamp}{self.nonce}".encode()
        return hashlib.sha512(block_string).hexdigest()
class MerkleTree:
    def __init__(self, transaction_hashes):
        self.transaction_hashes = transaction_hashes
        self.root, self.tree_levels = self.build_tree(transaction_hashes)  # Store all levels for proof generation

    def build_tree(self, leaves):
        """Builds the Merkle Tree iteratively and stores all levels for proof generation."""
        tree_levels = [leaves]  # Track each level of the tree
        while len(leaves) > 1:
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1])
            parent_layer = [hashlib.sha256((leaves[i] + leaves[i + 1]).encode()).hexdigest() 
                            for i in range(0, len(leaves), 2)]
            tree_levels.append(parent_layer)
            leaves = parent_layer
        return leaves[0] if leaves else None, tree_levels

    def get_proof(self, target_hash):
        """Generates a proof of inclusion path for a specific transaction hash."""
        index = self.transaction_hashes.index(target_hash)
        proof = []
        for level in self.tree_levels[:-1]:  # Exclude root level
            is_right_node = index % 2
            pair_index = index - 1 if is_right_node else index + 1
            if pair_index < len(level):
                proof.append((level[pair_index], "left" if is_right_node else "right"))
            index //= 2
        return proof

    @staticmethod
    def verify_proof(target_hash, proof, merkle_root):
        """Verifies a proof of inclusion given the target hash, proof, and merkle root."""
        computed_hash = target_hash
        for sibling_hash, position in proof:
            if position == "left":
                computed_hash = hashlib.sha256((sibling_hash + computed_hash).encode()).hexdigest()
            else:
                computed_hash = hashlib.sha256((computed_hash + sibling_hash).encode()).hexdigest()
        return computed_hash == merkle_root
class Blockchain:
    def is_transaction_in_block(self, block, transaction):
        """Verifies if a transaction exists in a block using Merkle proof of inclusion."""
        transaction_hash = transaction.compute_hash()
        merkle_tree = MerkleTree(block.transaction_hashes)
        proof = merkle_tree.get_proof(transaction_hash)
        return MerkleTree.verify_proof(transaction_hash, proof, block.merkle_root)
