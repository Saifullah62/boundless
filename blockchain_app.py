# blockchain_app.py

from flask import Flask, jsonify, render_template, request, redirect, url_for
from blockchain import Blockchain, Transaction, Block
import logging

# Initialize Flask app and Blockchain
app = Flask(__name__)
blockchain = Blockchain(difficulty=2)

# Home route to display dashboard
@app.route('/')
def index():
    return render_template("index.html", blockchain=blockchain.chain)

# Route to view full blockchain
@app.route('/blockchain', methods=['GET'])
def view_blockchain():
    chain_data = [blockchain.block_to_dict(block) for block in blockchain.chain]
    return jsonify(chain_data)

# Route to add a new transaction
@app.route('/new_transaction', methods=['POST'])
def new_transaction():
    sender = request.form.get("sender")
    receiver = request.form.get("receiver")
    amount = request.form.get("amount")
    
    if sender and receiver and amount:
        transaction = Transaction(sender, receiver, int(amount))
        new_block = Block(
            index=len(blockchain.chain),
            previous_hash=blockchain.get_latest_block().hash,
            transactions=[transaction]
        )
        blockchain.add_block(new_block)
        logging.info("Transaction added and block mined.")
    return redirect(url_for('index'))

# Route to validate the blockchain
@app.route('/validate', methods=['GET'])
def validate_blockchain():
    is_valid = blockchain.is_chain_valid()
    return jsonify({"is_valid": is_valid})

# Start Flask app
if __name__ == '__main__':
    app.run(debug=False)
