import pytest
from blockchain import Blockchain, Block, Transaction, MerkleTree

def test_create_genesis_block():
    # Test creation of the genesis block in the blockchain
    blockchain = Blockchain()
    genesis_block = blockchain.create_genesis_block()
    assert genesis_block is not None
    assert genesis_block.previous_hash == "0"
    assert genesis_block.index == 0

def test_add_block():
    # Test adding a block to the blockchain
    blockchain = Blockchain()
    genesis_block = blockchain.create_genesis_block()
    new_block = Block(1, genesis_block.hash, [Transaction("Alice", "Bob", 10)])
    blockchain.add_block(new_block)
    assert blockchain.get_latest_block().previous_hash == genesis_block.hash
    assert blockchain.get_latest_block().index == genesis_block.index + 1

def test_is_chain_valid():
    # Test validation of a tampered blockchain
    blockchain = Blockchain()
    genesis_block = blockchain.create_genesis_block()
    new_block = Block(1, genesis_block.hash, [Transaction("Alice", "Bob", 10)])
    blockchain.add_block(new_block)
    assert blockchain.is_chain_valid()  # Should be valid

    # Tamper with the blockchain to make it invalid
    blockchain.chain[1].transactions = [Transaction("Alice", "Mallory", 100)]
    assert not blockchain.is_chain_valid()  # Now should be invalid

def test_merkle_tree():
    # Test the Merkle Tree functionality
    transactions = [Transaction("Alice", "Bob", 10), Transaction("Bob", "Alice", 5)]
    merkle_tree = MerkleTree(transactions)
    assert merkle_tree.root is not None  # Check Merkle root is generated

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Generate private and public keys
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

# Serialize public key to PEM format to use it in transactions
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

# Create a new transaction and sign it with the private key
transaction = Transaction(sender=public_key_pem, receiver="receiver_address", amount=10.0, private_key=private_key)

# Print transaction details
print(f"Transaction: {transaction}")
print(f"Signature: {transaction.signature.hex()}")

