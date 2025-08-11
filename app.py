import os, base64
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_file
from dotenv import load_dotenv
import pymysql, bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.utils import secure_filename
from io import BytesIO

load_dotenv()
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', './uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'dev-secret')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
max_mb = int(os.environ.get('MAX_CONTENT_MB', 200))
app.config['MAX_CONTENT_LENGTH'] = max_mb * 1024 * 1024

AES_KEY_B64 = os.environ.get('AES_KEY')
if not AES_KEY_B64:
    raise RuntimeError('AES_KEY not set in environment. Run generate_keys.py and add AES_KEY to .env')
AES_KEY = base64.b64decode(AES_KEY_B64)
if len(AES_KEY) != 32:
    raise RuntimeError('AES_KEY must be 32 raw bytes (base64-encoded).')
aesgcm = AESGCM(AES_KEY)

def get_db_connection():
    return pymysql.connect(
        host=os.environ.get('MYSQL_HOST','localhost'),
        port=int(os.environ.get('MYSQL_PORT',3306)),
        user=os.environ.get('MYSQL_USER','root'),
        password=os.environ.get('MYSQL_PASSWORD',''),
        database=os.environ.get('MYSQL_DATABASE','file_transfer_db'),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )

# --- helpers ---
def create_user(username, password, role='user'):
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("INSERT INTO users (username, password_hash, role) VALUES (%s,%s,%s)", (username, pw_hash, role))
    conn.close()

def find_user_by_username(username):
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cur.fetchone()
    conn.close()
    return user

def ensure_tables():
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute(open('db_setup.sql').read())
    conn.close()
ensure_tables()

# --- auth routes ---
@app.route('/', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = find_user_by_username(username)
        if user and bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Logged in successfully.', 'success')
            return redirect(url_for('upload_file'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if find_user_by_username(username):
            flash('Username already taken', 'warning')
            return redirect(url_for('register'))
        create_user(username, password)
        flash('Account created. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapper

@app.route('/upload', methods=['GET','POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file supplied', 'warning')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'warning')
            return redirect(request.url)
        filename = secure_filename(file.filename)
        data = file.read()
        # AES-GCM: generate 12-byte nonce per file
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, data, None)
        stored_name = f"{session['user_id']}_{os.urandom(6).hex()}_{filename}.enc"            path = os.path.join(app.config['UPLOAD_FOLDER'], stored_name)
        with open(path, 'wb') as f:
            # store: nonce + ciphertext
            f.write(nonce + ct)
        filesize = len(data)
        # insert transfer record; store nonce separately for convenience (also stored in file)
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("INSERT INTO transfers (user_id, filename, stored_name, nonce, tag, filesize) VALUES (%s,%s,%s,%s,%s,%s)", (session['user_id'], filename, stored_name, None, None, filesize))
        conn.close()
        flash('File uploaded and encrypted successfully!', 'success')
        return redirect(url_for('upload_file'))
    return render_template('upload.html')

@app.route('/history')
@login_required
def history():
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT id, filename, stored_name, filesize, transfer_time FROM transfers WHERE user_id=%s ORDER BY transfer_time DESC", (session['user_id'],))
        transfers = cur.fetchall()
    conn.close()
    return render_template('history.html', transfers=transfers)

@app.route('/download/<int:transfer_id>')
@login_required
def download(transfer_id):
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM transfers WHERE id=%s AND user_id=%s", (transfer_id, session['user_id']))
        t = cur.fetchone()
    conn.close()
    if not t:
        abort(404)
    path = os.path.join(app.config['UPLOAD_FOLDER'], t['stored_name'])
    if not os.path.exists(path):
        abort(404)
    with open(path, 'rb') as f:
        raw = f.read()
    nonce = raw[:12]
    ct = raw[12:]
    try:
        pt = aesgcm.decrypt(nonce, ct, None)
    except Exception as e:
        flash('Decryption failed: invalid key or corrupted file', 'danger')
        return redirect(url_for('history'))
    return send_file(BytesIO(pt), as_attachment=True, download_name=t['filename'])

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
