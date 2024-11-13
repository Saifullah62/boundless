Boundless

Boundless is a blockchain application designed to securely connect to a blockchain network, manage private keys with encryption, and perform transactions with best-in-class security practices. By leveraging environment variables and cryptographic standards, Boundless ensures sensitive data is handled safely and configurations are easily managed across environments.
Features

    Secure handling of private keys and API keys through environment variables.
    Verification of required environment variables at startup to prevent configuration errors.
    Adheres to cryptographic standards to ensure data integrity and security.

Table of Contents

    Requirements
    Installation
    Configuration
    Usage
    Running Tests
    Best Practices
    Troubleshooting
    Contributing

Requirements

    Python 3.6+
    pip (Python package installer)

Installation

    Clone the Repository:

git clone https://github.com/your-username/boundless.git
cd boundless

Install Dependencies: Install the required Python packages listed in requirements.txt.

    pip install -r requirements.txt

Configuration

    Environment Variables: Boundless uses environment variables for sensitive information and network configurations. These variables are stored in a .env file located in the root directory.

    Create a .env File: In the root of the project, create a .env file and add the following variables:

    NETWORK_URL=https://example-blockchain-node.com
    API_KEY=your_api_key_here
    ENCRYPTED_PRIVATE_KEY=your_encrypted_private_key_here
    KEY_PASSWORD=your_password_here
    DEBUG=True

        Note: Make sure .env is listed in .gitignore to prevent sensitive information from being pushed to version control.

    Environment Variable Verification: Boundless checks that all required environment variables are set at startup. If any are missing, it raises an EnvironmentError with details about the missing variables, making it easy to troubleshoot configuration issues.

Usage

To run the application, use the main Python file blockchain.py:

python blockchain.py

Example Code Snippet

To call specific functions within Boundless, you can do so directly in blockchain.py. For example:

from blockchain import connect_to_blockchain, sign_transaction

# Example function call to connect to the blockchain
connect_to_blockchain()

# Example transaction signing
sign_transaction("sample transaction data")

Running Tests

To test the application, ensure all environment variables are configured. Run the tests using:

python -m unittest discover -s tests

Best Practices

    Security: Use a secure vault for sensitive environment variables in production. Encrypt .env files if they are stored on a shared server.
    Dependency Management: Regularly update requirements.txt to the latest compatible versions.
    Error Handling: Log errors for better debugging and traceability.

Troubleshooting

    Missing Environment Variables: If you encounter an EnvironmentError, ensure all variables in the .env file are correctly set.
    Connection Issues: Verify that NETWORK_URL and API_KEY are accurate and that your network allows access to the blockchain node.
    Decryption Issues with Private Key: Double-check that ENCRYPTED_PRIVATE_KEY and KEY_PASSWORD are correct and match the application’s format expectations.

Contributing

    Fork the repository.
    Create a new branch with a descriptive name.
    Commit your changes.
    Submit a pull request.

Example .gitignore

# Ignore .env file
.env
__pycache__/
*.pyc

