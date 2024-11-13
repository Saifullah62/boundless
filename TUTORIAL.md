Boundless Tutorial

Welcome to the Boundless Tutorial! This guide will take you through the complete setup process, from installation to running transactions, with easy-to-follow steps and code examples.
Table of Contents

    Introduction
    Setting Up Your Environment
    Installing Boundless
    Configuring Environment Variables
    Connecting to the Blockchain
    Signing a Transaction
    Running Tests
    Troubleshooting
    Additional Resources

1. Introduction

Boundless is a blockchain application designed to securely connect to a blockchain network and handle private key management. This tutorial will guide you through the steps necessary to get Boundless up and running on your local machine.
2. Setting Up Your Environment
Prerequisites

To run Boundless, you’ll need:

    Python 3.6+ installed on your system.
    pip (Python package installer) for installing dependencies.

To check if you have Python and pip, run the following commands:

python --version
pip --version

If you need Python, download it here.
3. Installing Boundless

    Clone the Repository: Start by cloning the Boundless repository to your local machine. Run:

git clone https://github.com/Saifullah62/boundless.git
cd boundless

Install Dependencies: Boundless requires several Python packages to function properly. Install these dependencies by running:

    pip install -r requirements.txt

        Note: requirements.txt includes essential packages like requests and python-dotenv.

4. Configuring Environment Variables

Boundless uses environment variables to manage sensitive information like API keys and private keys. We store these values in a .env file for security and flexibility.
Step-by-Step Setup for .env

    Create a .env file in the root of the Boundless project directory:

touch .env

Add the following environment variables to your .env file:

    NETWORK_URL=https://example-blockchain-node.com
    API_KEY=your_api_key_here
    ENCRYPTED_PRIVATE_KEY=your_encrypted_private_key_here
    KEY_PASSWORD=your_password_here
    DEBUG=True

    Verify Environment Variables: Boundless checks if all required variables are loaded. If a variable is missing, it will raise an EnvironmentError with the details of the missing configuration.

5. Connecting to the Blockchain

Once your environment is set up, you can connect to the blockchain network using the connect_to_blockchain function.
Example Code for Connecting

Add the following code to blockchain.py or create a separate script to test the connection:

from blockchain import connect_to_blockchain

response = connect_to_blockchain()
print("Connected to blockchain:", response)

This function makes a request to the specified blockchain node using NETWORK_URL and API_KEY.
6. Signing a Transaction

Boundless allows you to sign transactions securely by retrieving and decrypting your private key.
Example Code for Signing a Transaction

In blockchain.py, use the sign_transaction function to securely sign data with your private key:

from blockchain import sign_transaction

transaction_data = "Sample transaction data"
signature = sign_transaction(transaction_data)
print("Transaction signature:", signature)

    Note: sign_transaction will load your encrypted private key and password from the .env file, ensuring it remains secure.

7. Running Tests

To ensure Boundless functions correctly, you can run the test suite included in the repository. This will verify functionality like blockchain connectivity and transaction signing.

    Run Tests:

    python -m unittest discover -s tests

    Interpreting Results:
        If all tests pass, Boundless is correctly configured.
        If any test fails, refer to the error message for debugging.

8. Troubleshooting

Here are some common issues and solutions:

    Missing Environment Variables: If Boundless raises an EnvironmentError, check that your .env file contains all required variables.
    Connection Errors: Verify the NETWORK_URL and API_KEY. Ensure your network allows access to the specified blockchain node.
    Private Key Issues: Ensure ENCRYPTED_PRIVATE_KEY and KEY_PASSWORD in your .env file match the expected format for decryption.

9. Additional Resources

To learn more about blockchain and secure coding practices, consider these resources:

    Python Dotenv Documentation
    Blockchain Basics
    Cryptographic Best Practices
