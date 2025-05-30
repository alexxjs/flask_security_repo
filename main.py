# main.py

from flask import Flask, render_template, redirect, url_for, flash, request, jsonify  
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user, login_required
from config import Config
from models import db, User, Transaction, SecureMessage, AuditLog, SystemStatus
from auth import auth_bp
from secure_kms import load_decrypted_key
from encryption import decrypt_data, encrypt_data
from functools import wraps
from assets import ASSET_CATALOG
from password_validator import PasswordValidator
from datetime import datetime, timedelta
import subprocess

app = Flask(__name__)
app.config.from_object(Config)

# Initialize DB + LoginManager
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'
app.register_blueprint(auth_bp)

# Create tables
with app.app_context():
    db.create_all()

# testt

# Define password policy
password_policy = PasswordValidator()
password_policy \
    .min(8) \
    .max(64) \
    .has().uppercase() \
    .has().lowercase() \
    .has().digits() \
    .has().symbols() \
    .has().no().spaces()

# User loader
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def log_event(user_id, event):
    new_log = AuditLog(user_id=user_id, event=event)
    db.session.add(new_log)
    db.session.commit()


# Role decorators
def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role_name:
                flash("Access denied", "danger")
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return wrapped
    return decorator


# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/dashboard/admin')
@login_required
@role_required('admin')
def dashboard_admin():
    users = User.query.order_by(User.role, User.username).all()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    status = get_system_status()
    return render_template('dashboard_admin.html', users=users, logs=logs, system_status=status)


# CLIENT FEATURES


@app.route('/transactions')
@login_required
@role_required('client')
def view_transactions():
    key = load_decrypted_key()
    transactions = Transaction.query.filter_by(sender_id=current_user.id).all()
    verified = []

    for tx in transactions:
        try:
            decrypted = decrypt_data(tx.details_encrypted, key).decode() if tx.details_encrypted else ""
            hash_check = Transaction.generate_hash(tx.asset, tx.action, tx.quantity, decrypted)
            integrity_ok = (hash_check == tx.data_hash)
        except Exception:
            decrypted = "[Decryption Failed]"
            integrity_ok = False

        verified.append({
            "asset": tx.asset,
            "action": tx.action,
            "quantity": tx.quantity,
            "notes": decrypted,
            "timestamp": tx.timestamp,
            "integrity": integrity_ok
        })

    return render_template('transactions.html', transactions=verified)


from assets import ASSET_CATALOG

@app.route('/transaction/initiate', methods=['GET', 'POST'])
@login_required
@role_required('client')
def initiate_transaction():
    key = load_decrypted_key()

    if request.method == 'POST':
        asset = request.form['asset']
        action = request.form['action']
        quantity = float(request.form['quantity'])
        notes = request.form.get('notes', '')

        # Validate asset
        if asset not in ASSET_CATALOG:
            flash("Invalid asset selected", "danger")
            return redirect(url_for('initiate_transaction'))

        # Get asset price securely
        price_per_unit = ASSET_CATALOG[asset]
        total_cost = quantity * price_per_unit

        encrypted_notes = encrypt_data(notes.encode(), key)
        data_hash = Transaction.generate_hash(asset, action, quantity, notes)

        new_tx = Transaction(
            sender_id=current_user.id,
            asset=asset,
            action=action.upper(),
            quantity=quantity,
            details_encrypted=encrypted_notes,
            data_hash=data_hash
        )

        db.session.add(new_tx)
        db.session.commit()
        log_event(
            current_user.id,
            f"CLIENT submitted {action.upper()} {quantity}x {asset} for user_id={current_user.id}"
        )

        flash(f"Transaction submitted - Total cost: £{total_cost:.2f}", "success")
        return redirect(url_for('dashboard_client'))
    
    return render_template('transaction_form.html', assets=ASSET_CATALOG)

@app.route('/dashboard/client')
@login_required
@role_required('client')
def dashboard_client():
    from assets import ASSET_CATALOG
    key = load_decrypted_key()


    # Portfolio calculation 
    transactions = Transaction.query.filter_by(sender_id=current_user.id).all()
    holdings = {}
    for tx in transactions:
        asset = tx.asset
        qty = tx.quantity if tx.action == "BUY" else -tx.quantity
        holdings[asset] = holdings.get(asset, 0.0) + qty

    # Filter non-zero holdings
    filtered = {a: q for a, q in holdings.items() if q > 0}
    portfolio_data = []
    total_value = 0.0

    for asset, qty in filtered.items():
        price = ASSET_CATALOG.get(asset, 0.0)
        value = round(price * qty, 2)
        total_value += value
        portfolio_data.append({
            "asset": asset,
            "quantity": qty,
            "price": price,
            "value": value
        })

    # Recent transactions - decrypted 
    recent_tx = sorted(transactions, key=lambda x: x.timestamp, reverse=True)[:5]
    safe_tx = []
    for tx in recent_tx:
        try:
            decrypted = decrypt_data(tx.details_encrypted, key).decode() if tx.details_encrypted else ""
        except Exception:
            decrypted = "[Decryption Error]"
        safe_tx.append({
            "asset": tx.asset,
            "action": tx.action,
            "quantity": tx.quantity,
            "notes": decrypted,
            "timestamp": tx.timestamp
        })

    return render_template("dashboard_client.html",
                        portfolio=portfolio_data,
                        total_value=round(total_value, 2),
                        recent_tx=safe_tx,
                        assets=ASSET_CATALOG)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
@role_required('client')  
def update_profile():
    key = load_decrypted_key()
    user = current_user

    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        phone = request.form['phone']

        try:
            user.full_name = full_name
            user.email_encrypted = encrypt_data(email.encode(), key)
            user.phone_encrypted = encrypt_data(phone.encode(), key)
            db.session.commit()
            flash("Profile updated securely", "success")
        except Exception as e:
            flash("Error updating profile", "danger")

        return redirect(url_for('update_profile'))

    # Decrypt for display
    decrypted_email = user.get_email(key)
    decrypted_phone = user.get_phone(key)

    return render_template('profile.html',
                           full_name=user.full_name or "",
                           email=decrypted_email,
                           phone=decrypted_phone)


@app.route('/messages')
@login_required
def secure_messages():
    return "<h3>Secure Messages</h3><p>Encrypted messages with advisor will appear here</p>"


# ADVISOR FEATURES


@app.route('/dashboard/advisor', methods=['GET', 'POST'])
@login_required
@role_required('advisor')
def dashboard_advisor():
    selected_client = None
    all_clients = User.query.filter_by(role='client').all()

    if request.method == 'POST':
        selected_username = request.form.get('client_username')
        selected_client = User.query.filter_by(username=selected_username, role='client').first()

        if not selected_client:
            flash("Client not found.", "danger")

    return render_template('dashboard_advisor.html',
                           clients=all_clients,
                           selected_client=selected_client,
                           assets=ASSET_CATALOG,
                           key = load_decrypted_key())



@app.route('/advisor/submit', methods=['POST'])
@login_required
@role_required('advisor')
def submit_advisor_transaction():
    key = load_decrypted_key()
    client_id = request.form.get('client_id')
    asset = request.form.get('asset')
    action = request.form.get('action')
    quantity = float(request.form.get('quantity'))
    notes = request.form.get('notes', '')

    # Validate client
    client = User.query.filter_by(id=client_id, role='client').first()
    if not client:
        flash("Invalid client ID", "danger")
        return redirect(url_for('dashboard_advisor'))

    # Validate asset
    if asset not in ASSET_CATALOG:
        flash("Invalid asset selected", "danger")
        return redirect(url_for('dashboard_advisor'))

    # Encrypt notes
    encrypted_notes = encrypt_data(notes.encode(), key)

    # Hash data for integrity
    data_hash = Transaction.generate_hash(asset, action, quantity, notes)

    # Store transaction as if the client made it, but log advisors role for audit
    new_tx = Transaction(
        sender_id=client.id,
        asset=asset,
        action=action.upper(),
        quantity=quantity,
        details_encrypted=encrypted_notes,
        data_hash=data_hash
    )

    db.session.add(new_tx)
    db.session.commit()

    log_event(
        current_user.id,
        f"ADVISOR submitted {action.upper()} {quantity}x {asset} for user_id={client.id}"
    )

    flash(f"✅ Transaction for {client.username} submitted successfully.", "success")
    return redirect(url_for('dashboard_advisor'))

@app.route('/advisor/message', methods=['POST'])
@login_required
@role_required('advisor')
def advisor_message():
    recipient_id = request.form.get('client_id')
    message = request.form.get('message')
    key = load_decrypted_key()

    client = User.query.filter_by(id=recipient_id, role='client').first()
    if not client:
        return "Invalid client ID", 400

    encrypted = encrypt_data(message.encode(), key)

    msg = SecureMessage(
        sender_id=current_user.id,
        recipient_id=client.id,
        body_encrypted=encrypted
    )
    db.session.add(msg)
    db.session.commit()

    return "Message sent securely", 200


@app.route('/assign-client/<int:client_id>', methods=['POST'])
@login_required
@role_required('advisor')
def assign_client(client_id):
    client = User.query.filter_by(id=client_id, role='client').first()

    if not client:
        flash("Client not found.", "danger")
        return redirect(url_for('dashboard_advisor'))

    if client.advisor_id:
        flash(f"Client already assigned to {client.advisor.username}.", "warning")
        return redirect(url_for('dashboard_advisor'))

    client.advisor_id = current_user.id
    db.session.commit()
    flash("You are now assigned to this client.", "success")
    return redirect(url_for('dashboard_advisor'))



# ADMIN FEATURES

@app.route('/admin/run-patch-check', methods=['POST'])
@login_required
@role_required('admin')
def run_patch_check():
    import subprocess
    from datetime import datetime, timedelta

    status = get_system_status()

    # Get list of outdated packages
    result = subprocess.run(
        ['pip', 'list', '--outdated'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    lines = result.stdout.strip().split('\n')
    outdated_lines = lines[2:]  # Skip the table headers

    updated_count = 0
    updated_packages = []

    for line in outdated_lines:
        columns = line.split()
        if len(columns) >= 1:
            package = columns[0]
            subprocess.run(['pip', 'install', '--upgrade', package])
            updated_packages.append(package)
            updated_count += 1

    # Update status tracking
    status.last_patch_check = datetime.utcnow()
    status.next_recommended_check = datetime.utcnow() + timedelta(days=30)
    db.session.commit()

    # Log it
    log_event(current_user.id, f"Ran patch check — {updated_count} packages updated")

    if updated_count > 0:
        pkg_list = ', '.join(updated_packages)
        flash(f"Patch check complete: {updated_count} packages updated: {pkg_list}", "success")
    else:
        flash("All packages were up to date", "info")

    return redirect(url_for('dashboard_admin'))

@app.route('/admin/edit-user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    key = load_decrypted_key()


    if request.method == 'POST':
        user.full_name = request.form['full_name']
        user.role = request.form['role']
        user.is_active = 'is_active' in request.form

        # Encrypt sensitive fields
        user.email_encrypted = encrypt_data(request.form['email'].encode(), key)
        user.phone_encrypted = encrypt_data(request.form['phone'].encode(), key)

        db.session.commit()
        log_event(current_user.id, f"Edited user {user.username}: role={user.role}, status={'active' if user.is_active else 'inactive'}")
        flash(f"Updated user {user.username}", "success")
        return redirect(url_for('dashboard_admin'))

    # Decrypt to show current values
    email = decrypt_data(user.email_encrypted, key).decode()
    phone = decrypt_data(user.phone_encrypted, key).decode() if user.phone_encrypted else ''

    return render_template('edit_user.html', user=user, email=email, phone=phone)



@app.route('/admin/deactivate-user/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def deactivate_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = False
    db.session.commit()
    log_event(current_user.id, f"Deactivated user: {user.username}")
    flash(f"User {user.username} deactivated", "warning")
    return redirect(url_for('dashboard_admin'))

@app.route('/admin/create-user', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def create_user():
    key = load_decrypted_key()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        full_name = request.form['full_name']
        email = request.form['email']
        phone = request.form['phone']
        role = request.form['role']

        if not password_policy.validate(password):
            flash("Password must be 8–64 chars with uppercase, lowercase, number, symbol, and no spaces.", "danger")
            return redirect(url_for('create_user'))

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for('create_user'))

        new_user = User(
            username=username,
            full_name=full_name,
            role=role,
            email_encrypted=encrypt_data(email.encode(), key)
        )
        new_user.phone_encrypted = encrypt_data(phone.encode(), key)
        new_user.is_active = True
        new_user.assign_password(password)

        db.session.add(new_user)
        db.session.commit()

        log_event(current_user.id, f"Created new user: {username} ({role})")
        flash(f"User {username} created successfully.", "success")
        return redirect(url_for('dashboard_admin'))

    return render_template('create_user.html')

@app.route('/portfolio')
@login_required
@role_required('client')
def view_portfolio():
    transactions = Transaction.query.filter_by(sender_id=current_user.id).all()
    portfolio = {}

    for tx in transactions:
        asset = tx.asset
        quantity = tx.quantity if tx.action == 'BUY' else -tx.quantity
        portfolio[asset] = portfolio.get(asset, 0.0) + quantity

    # Filter out assets with 0 or negative balance
    filtered = {asset: qty for asset, qty in portfolio.items() if qty > 0}

    portfolio_view = []
    total_value = 0.0

    for asset, qty in filtered.items():
        price = ASSET_CATALOG.get(asset, 0.0)
        value = round(price * qty, 2)
        total_value += value
        portfolio_view.append({
            'asset': asset,
            'quantity': qty,
            'price': price,
            'value': value
        })

    return render_template('portfolio.html', portfolio=portfolio_view, total=round(total_value, 2))


#### MESSAGING ######

@app.route('/messages/<int:peer_id>')
@login_required
def get_messages(peer_id):
    key = load_decrypted_key()


    peer_user = User.query.get(peer_id)
    if not peer_user:
        return "User not found", 404

    # Client is logged in
    if current_user.role == 'client':
        if peer_user.role != 'advisor' or current_user.advisor_id != peer_id:
            return "Unauthorized", 403

    # Advisor is logged in
    if current_user.role == 'advisor':
        if peer_user.role != 'client' or peer_user.advisor_id != current_user.id:
            return "Unauthorized", 403

    # Get all messages between the two
    messages = SecureMessage.query.filter(
        ((SecureMessage.sender_id == current_user.id) & (SecureMessage.recipient_id == peer_id)) |
        ((SecureMessage.sender_id == peer_id) & (SecureMessage.recipient_id == current_user.id))
    ).order_by(SecureMessage.timestamp.asc()).all()

    result = []
    for msg in messages:
        try:
            body = decrypt_data(msg.body_encrypted, key).decode()
        except Exception:
            body = "[Decryption Failed]"

        result.append({
            "sender": msg.sender_user.username,
            "recipient": msg.recipient_user.username,
            "body": body,
            "timestamp": msg.timestamp.strftime('%Y-%m-%d %H:%M')
        })
    return jsonify(result)

@app.route('/messages/send', methods=['POST'])
@login_required
def send_message():
    key = load_decrypted_key()

    recipient_id = int(request.form['recipient_id'])
    message = request.form['message']

    recipient = User.query.filter_by(id=recipient_id).first()
    if not recipient:
        return "Recipient not found", 404

    # Advisors can message anyone; clients only their advisor
    if current_user.role == 'client' and recipient.role != 'advisor':
        return "Unauthorised", 403

    encrypted = encrypt_data(message.encode(), key)
    msg = SecureMessage(
        sender_id=current_user.id,
        recipient_id=recipient_id,
        body_encrypted=encrypted
    )
    db.session.add(msg)
    db.session.commit()

    return "Message sent", 200

@app.route('/chat/<int:peer_id>')
@login_required
def chat_view(peer_id):

    if current_user.role == 'client' and current_user.advisor_id != peer_id:
        return "Unauthorised", 403

    peer_user = User.query.get(peer_id)
    if not peer_user:
        return "User not found", 404

    if current_user.role == 'advisor':
        client = User.query.filter_by(id=peer_id, role='client').first()
        if not client or client.advisor_id != current_user.id:
            return "Unauthorised", 403

    return render_template('chat.html', peer_user=peer_user)

@app.route('/inbox')
@login_required
@role_required('client')
def inbox():
    key = load_decrypted_key()

    messages = SecureMessage.query.filter_by(recipient_id=current_user.id).order_by(SecureMessage.timestamp.desc()).all()

    decrypted_messages = []
    for msg in messages:
        try:
            body = decrypt_data(msg.body_encrypted, key).decode()
        except:
            body = "[Decryption Failed]"

        decrypted_messages.append({
            "from": msg.sender_user.username,
            "body": body,
            "timestamp": msg.timestamp.strftime('%Y-%m-%d %H:%M')
        })

    return render_template('inbox.html', messages=decrypted_messages)

def get_system_status():
    status = SystemStatus.query.get(1)
    if not status:
        from datetime import datetime, timedelta
        status = SystemStatus(
            id=1,
            last_patch_check=datetime.utcnow(),
            next_recommended_check=datetime.utcnow() + timedelta(days=30)
        )
        db.session.add(status)
        db.session.commit()
    return status



# Run the app
if __name__ == '__main__':
    app.run(ssl_context=('certs/server.crt', 'certs/server.key'))