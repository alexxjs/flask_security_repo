# seed_users.py

from flask import Flask
from config import Config
from models import db, User, SecureMessage
from encryption import encrypt_data
from secure_kms import load_encrypted_key
import pyotp

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

key = load_encrypted_key()

users = [
    {
        "username": "client1",
        "email": "client1@myfinance.com",
        "password": "pass123",
        "role": "client",
        "full_name": "Alice Investor",
        "phone_number": "07700112233"
    },
    {
        "username": "advisor1",
        "email": "advisor1@myfinance.com",
        "password": "pass123",
        "role": "advisor",
        "full_name": "Bob Advisor",
        "phone_number": "07700445566"
    },
    {
        "username": "admin1",
        "email": "admin1@myfinance.com",
        "password": "pass123",
        "role": "admin",
        "full_name": "Charlie Admin",
        "phone_number": "07700998877"
    }
]

with app.app_context():
    db.drop_all()
    db.create_all()

    for u in users:
        if not User.query.filter_by(username=u["username"]).first():
            encrypted_email = encrypt_data(u["email"].encode(), key)
            encrypted_phone = encrypt_data(u["phone_number"].encode(), key)

            user = User(
                username=u["username"],
                email_encrypted=encrypted_email,
                role=u["role"],
                full_name=u["full_name"]
            )
            user.phone_encrypted = encrypted_phone
            user.set_password(u["password"])
            user.two_factor_secret = pyotp.random_base32()
            user.two_factor_enabled = False

            db.session.add(user)
            print(f"Added: {u['username']} ({u['role']})")

    db.session.commit()
    print("✅ Demo users seeded successfully.")
