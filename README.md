# Boundless Blockchain

Boundless Blockchain is a simple Proof-of-Work blockchain implemented in Python. This project serves as an educational introduction to the concepts behind blockchain technology, hashing, mining, and block verification, following a model inspired by Bitcoin's design principles. 

## Project Overview

The Boundless Blockchain project aims to help users understand how a basic blockchain works, focusing on:
- **Hashing**: Securing data with SHA-256.
- **Block Structure**: Storing data in individual blocks.
- **Proof-of-Work**: Mining new blocks by finding valid hashes.
- **Chain Verification**: Ensuring the integrity of the entire chain.

Boundless Blockchain consists of two main files:
- **blockchain.py**: Contains the `Block` and `Blockchain` classes, along with methods for mining, linking blocks, and verifying the chain.
- **test_blockchain.py**: A script to test and demonstrate the functionality of `blockchain.py` by creating a blockchain, mining blocks, and validating the chain.

## Features

- **Genesis Block**: Initializes the chain with a single root block.
- **Block Mining**: Mines each block by adjusting the `nonce` until the hash meets a specified difficulty.
- **Chain Integrity**: Verifies each block's link to ensure no tampering has occurred.

## Installation

### Prerequisites
This project requires Python 3.6+.

### Setup Instructions
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/boundless-blockchain.git
   cd boundless-blockchain
