# seed_investments.py

from flask import Flask
from config import Config
from models import db, User, Investment
from encryption import encrypt_data
from secure_kms import load_encrypted_key

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

key = load_encrypted_key()

with app.app_context():
    db.create_all()

    client = User.query.filter_by(username="client1").first()

    if not client:
        print("client1 not found - seed users first.")
        exit()

    investments_data = [
        {
            "asset_name": "Apple Stock",
            "quantity": 15,
            "current_value": 2500.00,
            "notes": "Long-term hold - strong earnings expected"
        },
        {
            "asset_name": "UK Government Bonds",
            "quantity": 50,
            "current_value": 5000.00,
            "notes": "Low risk"
        },
        {
            "asset_name": "Bitcoin",
            "quantity": 0.75,
            "current_value": 21000.00,
            "notes": "High volatility — monitor more often"
        }
    ]

    for inv in investments_data:
        encrypted_notes = encrypt_data(inv["notes"].encode(), key)
        new_inv = Investment(
            client_id=client.id,
            asset_name=inv["asset_name"],
            quantity=inv["quantity"],
            current_value=inv["current_value"],
            notes_encrypted=encrypted_notes
        )
        db.session.add(new_inv)

    db.session.commit()
    print("Encrypted investments added to client1's portfolio.")
