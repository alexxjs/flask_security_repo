# auth.py

from flask import Blueprint, request, render_template, redirect, url_for, flash, session, send_file, abort
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash
from sqlalchemy.sql import text
from models import db, User, AuditLog
from encryption import encrypt_data, decrypt_data
from secure_kms import load_decrypted_key
import qrcode
import pyotp
from io import BytesIO

auth_bp = Blueprint('auth', __name__)
key = load_decrypted_key()


def get_valid_roles(login_type):
    if login_type == 'employee':
        return ['advisor', 'admin']
    return ['client']

def log_event(user_id, event):
    new_log = AuditLog(user_id=user_id, event=event)
    db.session.add(new_log)
    db.session.commit()


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    key = load_decrypted_key()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        phone = request.form['phone']

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for('auth.register'))

        encrypted_email = encrypt_data(email.encode(), key)
        encrypted_phone = encrypt_data(phone.encode(), key)

        user = User(username=username, email_encrypted=encrypted_email, full_name="", role='client')
        user.phone_encrypted = encrypted_phone
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        log_event(user.id, f"Registered new account")

        login_user(user)
        return redirect(url_for('auth.setup_2fa'))

    return render_template('register.html')




@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    role = request.args.get('role', 'client')

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password) and user.role in get_valid_roles(role):
            log_event(user.id, "Logged in successfully")
            if user.two_factor_enabled:
                # Store user temporarily
                session['pending_2fa_user'] = user.id
                return redirect(url_for('auth.verify_2fa'))
            else:
                login_user(user)
                return redirect(url_for(f'dashboard_{user.role}'))
            
        log_event(None, f"Failed login attempt - username={username}")    
        flash("Invalid credentials or role mismatch", "danger")

    return render_template('login.html', role=role, show_2fa=False)

@auth_bp.route('/generate_qr', endpoint='generate_qr')
@login_required
def generate_qr():
    """Generate and return QR code as an image for embedding in 2FA setup"""
    user = current_user
    if not user.two_factor_secret:
        abort(404, "2FA secret not found")

    totp = pyotp.TOTP(user.two_factor_secret)
    qr_code_url = totp.provisioning_uri(
        name=f"{user.username}@MyFinance",
        issuer_name="MyFinance Inc."
    )

    qr_image = qrcode.make(qr_code_url)
    buffer = BytesIO()
    qr_image.save(buffer, format="PNG")
    buffer.seek(0)

    return send_file(buffer, mimetype='image/png')

@auth_bp.route('/setup_2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    user = User.query.get(current_user.id)
    if not user.two_factor_secret:
        user.two_factor_secret = pyotp.random_base32()
        db.session.commit()

    if request.method == 'POST':
        otp = request.form.get('otp')
        totp = pyotp.TOTP(user.two_factor_secret)
        if totp.verify(otp):
            user.two_factor_enabled = True
            db.session.commit()
            flash("2FA enabled", "success")
            return redirect(url_for(f'dashboard_{current_user.role}'))

        flash("Invalid OTP", "danger")

    return render_template('setup_2fa.html')





@auth_bp.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    user_id = session.get('pending_2fa_user')
    if not user_id:
        flash("Session expired or invalid access", "danger")
        return redirect(url_for('auth.login'))

    user = User.query.get(user_id)

    if request.method == 'POST':
        otp = request.form.get('otp')
        totp = pyotp.TOTP(user.two_factor_secret)
        if totp.verify(otp, valid_window=1):
            log_event(user.id, "Logged in successfully")
            login_user(user)
            session.pop('pending_2fa_user', None)
            flash("2FA verified", "success")
            return redirect(url_for(f'dashboard_{user.role}'))

        else:
            flash("Invalid 2FA code.", "danger")

    return render_template('verify_2fa.html')



@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('auth.login'))
