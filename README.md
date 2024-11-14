Blockchain Network with Compliance and AI-enhanced Security

This repository provides an advanced blockchain network featuring peer-to-peer communication, compliance tracking, anomaly detection via machine learning, and AI-enhanced mining optimization. The codebase is equipped for regulatory compliance and implements privacy-preserving features like data encryption and user consent tracking.
Features

    Blockchain Core: Implements basic blockchain structures, including Blocks, Transactions, and a Merkle Tree.
    Peer-to-Peer Networking: Nodes communicate, share blocks, and transactions through secure sockets using TLS.
    Enhanced Compliance Tools: Modules for compliance checks, geographical origin detection, regulatory enforcement, and transaction nullification.
    Anomaly Detection: Uses Isolation Forest for AI-based anomaly detection on transaction patterns.
    Encrypted Data Storage: Transactions are encrypted using Fernet symmetric encryption.
    Multi-signature Transactions: Supports multi-signature transactions, requiring multiple parties to validate.
    Mining Optimization: Enhanced mining control for resource-efficient block creation.

Installation
Requirements

    Python 3.8+

    Required libraries (install with pip):

    pip install cryptography pyopenssl numpy scikit-learn

Setting Up the Environment

    SSL Certificates: Generate SSL certificates for secure peer-to-peer communication:

openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365

Environment Variables: Store an ACCESS_TOKEN in a .env file for secure peer authentication. This token verifies access permissions among peers.

    ACCESS_TOKEN=your_secure_token_here

Structure Overview

The codebase contains the following main components:

    Blockchain Core: Core blockchain structures (Block, Blockchain, Merkle Tree).
    Networking and P2P Communication: Server and client code for secure peer-to-peer connections and blockchain synchronization.
    Compliance and Privacy Tools: GeoSovereign for detecting data origin, RegBlock for applying regional laws, TransparencySuite for consent tracking, and ErasureGuard for transaction nullification.
    Machine Learning for Security: Anomaly detection using Isolation Forest to flag suspicious transactions.
    Blockchain Nodes: Specialized nodes with varying functionalities—enhanced for compliance, encryption, and AI-based anomaly detection.

Key Classes
1. Blockchain Core

    Block: Represents a block, containing transactions, previous hash, Merkle root, and timestamp.
    Transaction: Represents a transaction with methods for signing and verification.
    Blockchain: Manages the chain of blocks, including block creation, validation, and mining.

2. Compliance and Privacy Modules

    GeoSovereign: Detects the origin of transaction data and supports regional compliance.
    RegBlock: Enforces compliance based on detected geographic origin (e.g., GDPR for EU transactions).
    TransparencySuite: Tracks user consent for data usage, providing control over data privacy.
    ErasureGuard: Supports "right to be forgotten" by nullifying specified transactions.

3. Networking and Peer-to-Peer Communication

    start_server: Starts a server to manage peer connections, handle transaction requests, and synchronize chains.
    Peer-to-Peer Synchronization: Nodes share and synchronize their chains for consistency.

4. Machine Learning Anomaly Detection

    Isolation Forest: Utilized within the BlockchainNodeAI class to detect anomalous transaction patterns.
    Anomaly Detection Workflow: Converts transactions to numerical representations for model training and prediction.

Usage Examples
Initializing a Node

node = BlockchainNodeAI("Node_A", difficulty=3)

Adding Peers

node.add_peer("127.0.0.1:5001")
node.add_peer("127.0.0.1:5002")

Generating Transactions

transaction = Transaction("Alice", "Bob", 50)
node.receive_transaction(transaction)

Mining Blocks

node.mine_block()

Synchronizing with Peers

node.sync_with_peers()

Running Anomaly Detection

The BlockchainNodeAI class automatically applies anomaly detection when transactions are received. Transactions flagged as anomalous are discarded before reaching the chain.
Conducting Compliance Audits

node.perform_audit()

Running the Network

To test the blockchain network, simulate multiple nodes by creating instances of BlockchainNodeSecure or BlockchainNodeAI. Each node instance can manage its blockchain, receive transactions, and sync with peers.
Sample Simulation

if __name__ == "__main__":
    # Create nodes
    node_A = BlockchainNodeSecure("Node_A", difficulty=2)
    node_B = BlockchainNodeSecure("Node_B", difficulty=2)

    # Add peers
    node_A.add_peer(node_B)
    node_B.add_peer(node_A)

    # Generate and receive transactions
    tx1 = Transaction("Alice", "Bob", 100)
    node_A.receive_transaction(tx1)

    # Mine blocks
    node_A.mine_block()
    node_B.mine_block()

    # Synchronize chains
    node_A.sync_with_peers()

Advanced Modules

The following are additional features for enhanced security and compliance:

    Data Encryption: Encrypts transaction data with Fernet to protect data at rest.
    Regulatory Compliance Simulation: Applies regulatory rules per region through RegBlock.
    Data Audit: The ComplianceAuditToolkit provides an auditing mechanism for verifying chain transactions’ compliance status.
