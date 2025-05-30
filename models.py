# models.py

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from encryption import decrypt_data, encrypt_data
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib

db = SQLAlchemy()



# -----------------------------
# USERS (All roles)
# -----------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # client, advisor, admin
    email_encrypted = db.Column(db.LargeBinary, nullable=False)
    account_number = db.Column(db.String(16), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=True)
    phone_encrypted = db.Column(db.LargeBinary, nullable=True)
    two_factor_secret = db.Column(db.String(32), nullable=True)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    advisor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    advisor = db.relationship('User', remote_side='User.id')
    is_active = db.Column(db.Boolean, default=True)



    # Relationships
    investments = db.relationship('Investment', backref='client', lazy=True)


    def __init__(self, username, email_encrypted, role="client", account_number=None, full_name=None, phone_number=None):
        self.username = username
        self.email_encrypted = email_encrypted
        self.role = role
        self.account_number = account_number or self.generate_account_number()
        self.full_name = full_name
        self.phone_number = phone_number

    def is_active(self):
        return self.is_active
    @staticmethod
    def generate_account_number():
        from random import randint
        return f"ACC-{randint(10000, 99999)}"

    def set_password(self, password):
        self.password = generate_password_hash(password, method="pbkdf2:sha256")

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'
    
    def get_email(self, key):
        return decrypt_data(self.email_encrypted, key).decode()

    def get_phone(self, key):
        if self.phone_encrypted:
            return decrypt_data(self.phone_encrypted, key).decode()
        return ""


# -----------------------------
# INVESTMENT PORTFOLIO (Client)
# -----------------------------
class Investment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    asset_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    current_value = db.Column(db.Float, nullable=False)
    notes_encrypted = db.Column(db.LargeBinary, nullable=True)

    def __repr__(self):
        return f'<Investment {self.asset_name} ({self.quantity})>'



# -----------------------------
# TRANSACTIONS (Client/Advisor)
# -----------------------------


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    asset = db.Column(db.String(100), nullable=False)
    action = db.Column(db.String(10), nullable=False)  # BUY or SELL
    quantity = db.Column(db.Float, nullable=False)
    details_encrypted = db.Column(db.LargeBinary, nullable=True)
    data_hash = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    sender = db.relationship('User', backref='transactions')

    @staticmethod
    def generate_hash(asset, action, quantity, details):
        """Secure SHA-256 hash for transaction integrity."""
        hasher = hashlib.sha256()
        combined = f"{asset}:{action}:{quantity}:{details}".encode()
        hasher.update(combined)
        return hasher.hexdigest()



# -----------------------------
# SECURE MESSAGES (Advisor ↔ Client)
# -----------------------------


class SecureMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    sender_user = db.relationship('User', foreign_keys=[sender_id], backref='messages_sent')
    recipient_user = db.relationship('User', foreign_keys=[recipient_id], backref='messages_received')

    body_encrypted = db.Column(db.LargeBinary, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.current_timestamp())




# -----------------------------
# AUDIT LOGS (Admin view)
# -----------------------------
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    event = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User')

class SystemStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    last_patch_check = db.Column(db.DateTime, nullable=True)
    next_recommended_check = db.Column(db.DateTime, nullable=True)
