from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
import sqlite3
import bcrypt
import re
import os
import smtplib
import random
import string
import requests
import secrets
import base64
from urllib.parse import urlencode
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__, template_folder='../frontend/templates', static_folder='../frontend/static')
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-here')
socketio = SocketIO(app, cors_allowed_origins="*")
ONLINE_USERS = set()
from datetime import timedelta
app.permanent_session_lifetime = timedelta(days=7)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False

PROTECTED_ROUTES = ['/dashboard', '/messages', '/friends', '/send-friend-request', '/get-friend-requests', 
                   '/respond-friend-request', '/change-password']

@app.before_request
def check_auth():

    if request.endpoint in ['index', 'login_submit', 'register_user', 'verify_otp', 'forgot_password', 
                           'verify_reset_otp', 'reset_password', 'google_login', 'google_callback',
                           'features', 'about', 'contact', 'favicon', 'auth', 'service_worker']:
        return

    if any(request.path.startswith(route) for route in PROTECTED_ROUTES):
        if 'user_id' not in session:
            session.clear()
            flash('Please login to continue')
            return redirect(url_for('index'))


GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI')


EMAIL_CONFIG = {
    'sender_email': os.getenv('SENDER_EMAIL'),
    'sender_password': os.getenv('SENDER_PASSWORD'),
    'smtp_server': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
    'smtp_port': int(os.getenv('SMTP_PORT', 587))
}

def get_db_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'database', 'users.db')

def init_db():
    db_path = get_db_path()

    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    c.execute('PRAGMA journal_mode=WAL')
    c.execute('PRAGMA synchronous=NORMAL')
    c.execute('PRAGMA cache_size=10000')
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password TEXT,
                  verified INTEGER DEFAULT 0,
                  status TEXT DEFAULT 'Active',
                  profile_picture TEXT,
                  theme TEXT DEFAULT 'light',
                  bio TEXT,
                  interests TEXT,
                  privacy_settings TEXT DEFAULT '{}',
                  notification_settings TEXT DEFAULT '{}',
                  last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  online_status TEXT DEFAULT 'offline',
                  two_factor_enabled INTEGER DEFAULT 0,
                  two_factor_secret TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')  
    c.execute('''CREATE TABLE IF NOT EXISTS otp_codes
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT NOT NULL,
                  otp TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  expires_at TIMESTAMP NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS login_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  login_date DATE NOT NULL,
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  UNIQUE(user_id, login_date))''')
    c.execute('''CREATE TABLE IF NOT EXISTS friend_requests
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  sender_id INTEGER NOT NULL,
                  receiver_id INTEGER NOT NULL,
                  status TEXT DEFAULT 'pending',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (sender_id) REFERENCES users (id),
                  FOREIGN KEY (receiver_id) REFERENCES users (id),
                  UNIQUE(sender_id, receiver_id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS contact_messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  email TEXT NOT NULL,
                  subject TEXT NOT NULL,
                  message TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  sender_id INTEGER NOT NULL,
                  receiver_id INTEGER NOT NULL,
                  content TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  seen INTEGER DEFAULT 0,
                  delivered INTEGER DEFAULT 0,
                  status TEXT DEFAULT 'sent',
                  message_type TEXT DEFAULT 'text',
                  file_url TEXT,
                  file_name TEXT,
                  file_size INTEGER,
                  reply_to_id INTEGER,
                  forwarded_from INTEGER,
                  encrypted INTEGER DEFAULT 0,
                  scheduled_at TIMESTAMP,
                  FOREIGN KEY (sender_id) REFERENCES users (id),
                  FOREIGN KEY (receiver_id) REFERENCES users (id),
                  FOREIGN KEY (reply_to_id) REFERENCES messages (id),
                  FOREIGN KEY (forwarded_from) REFERENCES messages (id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS deleted_messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  message_id INTEGER NOT NULL,
                  deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  FOREIGN KEY (message_id) REFERENCES messages (id),
                  UNIQUE(user_id, message_id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS blocked_users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  blocker_id INTEGER NOT NULL,
                  blocked_id INTEGER NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (blocker_id) REFERENCES users (id),
                  FOREIGN KEY (blocked_id) REFERENCES users (id),
                  UNIQUE(blocker_id, blocked_id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS muted_users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  muter_id INTEGER NOT NULL,
                  muted_id INTEGER NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (muter_id) REFERENCES users (id),
                  FOREIGN KEY (muted_id) REFERENCES users (id),
                  UNIQUE(muter_id, muted_id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS admin_notifications
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  email TEXT NOT NULL,
                  subject TEXT NOT NULL,
                  message TEXT NOT NULL,
                  status TEXT NOT NULL DEFAULT 'queued',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS settings
                 (key TEXT PRIMARY KEY,
                  value TEXT NOT NULL,
                  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    c.execute('''CREATE TABLE IF NOT EXISTS groups
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  description TEXT,
                  creator_id INTEGER NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  is_private INTEGER DEFAULT 0,
                  group_picture TEXT,
                  FOREIGN KEY (creator_id) REFERENCES users (id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS group_announcements
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  group_id INTEGER NOT NULL,
                  user_id INTEGER NOT NULL,
                  content TEXT NOT NULL,
                  pinned INTEGER DEFAULT 1,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (group_id) REFERENCES groups (id),
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS group_members
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  group_id INTEGER NOT NULL,
                  user_id INTEGER NOT NULL,
                  role TEXT DEFAULT 'member',
                  joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (group_id) REFERENCES groups (id),
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  UNIQUE(group_id, user_id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS message_reactions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  message_id INTEGER NOT NULL,
                  user_id INTEGER NOT NULL,
                  reaction TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (message_id) REFERENCES messages (id),
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  UNIQUE(message_id, user_id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS group_announcements
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  group_id INTEGER NOT NULL,
                  user_id INTEGER NOT NULL,
                  content TEXT NOT NULL,
                  pinned INTEGER DEFAULT 1,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (group_id) REFERENCES groups (id),
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS group_events
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  group_id INTEGER NOT NULL,
                  creator_id INTEGER NOT NULL,
                  title TEXT NOT NULL,
                  description TEXT,
                  event_date TIMESTAMP NOT NULL,
                  location TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (group_id) REFERENCES groups (id),
                  FOREIGN KEY (creator_id) REFERENCES users (id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS group_polls
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  group_id INTEGER NOT NULL,
                  creator_id INTEGER NOT NULL,
                  question TEXT NOT NULL,
                  options TEXT NOT NULL,
                  expires_at TIMESTAMP,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (group_id) REFERENCES groups (id),
                  FOREIGN KEY (creator_id) REFERENCES users (id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS group_poll_votes
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  poll_id INTEGER NOT NULL,
                  user_id INTEGER NOT NULL,
                  option_index INTEGER NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (poll_id) REFERENCES group_polls (id),
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  UNIQUE(poll_id, user_id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS group_members
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  group_id INTEGER NOT NULL,
                  user_id INTEGER NOT NULL,
                  role TEXT DEFAULT 'member',
                  joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (group_id) REFERENCES groups (id),
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  UNIQUE(group_id, user_id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS group_messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  group_id INTEGER NOT NULL,
                  sender_id INTEGER NOT NULL,
                  content TEXT NOT NULL,
                  message_type TEXT DEFAULT 'text',
                  file_url TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (group_id) REFERENCES groups (id),
                  FOREIGN KEY (sender_id) REFERENCES users (id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS favorites
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  item_type TEXT NOT NULL,
                  item_id INTEGER NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  UNIQUE(user_id, item_type, item_id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS file_uploads
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  filename TEXT NOT NULL UNIQUE,
                  original_name TEXT NOT NULL,
                  file_size INTEGER NOT NULL,
                  file_type TEXT NOT NULL,
                  uploader_id INTEGER NOT NULL,
                  file_data TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (uploader_id) REFERENCES users (id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS message_reactions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  message_id INTEGER NOT NULL,
                  user_id INTEGER NOT NULL,
                  reaction_type TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (message_id) REFERENCES messages (id),
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  UNIQUE(message_id, user_id, reaction_type))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS voice_messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  message_id INTEGER NOT NULL,
                  audio_data TEXT NOT NULL,
                  duration INTEGER NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (message_id) REFERENCES messages (id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS user_stories
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  content TEXT NOT NULL,
                  media_type TEXT DEFAULT 'text',
                  media_url TEXT,
                  expires_at TIMESTAMP NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS message_templates
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  name TEXT NOT NULL,
                  content TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS scheduled_messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  sender_id INTEGER NOT NULL,
                  receiver_id INTEGER NOT NULL,
                  content TEXT NOT NULL,
                  message_type TEXT DEFAULT 'text',
                  scheduled_at TIMESTAMP NOT NULL,
                  sent INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (sender_id) REFERENCES users (id),
                  FOREIGN KEY (receiver_id) REFERENCES users (id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS typing_indicators
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  chat_id INTEGER NOT NULL,
                  chat_type TEXT DEFAULT 'user',
                  is_typing INTEGER DEFAULT 0,
                  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  UNIQUE(user_id, chat_id, chat_type))''')
    
    c.execute("PRAGMA table_info(messages)")
    message_columns = [column[1] for column in c.fetchall()]
    if 'message_type' not in message_columns:
        c.execute("ALTER TABLE messages ADD COLUMN message_type TEXT DEFAULT 'text'")
    if 'file_url' not in message_columns:
        c.execute("ALTER TABLE messages ADD COLUMN file_url TEXT")
    if 'file_name' not in message_columns:
        c.execute("ALTER TABLE messages ADD COLUMN file_name TEXT")
    if 'file_size' not in message_columns:
        c.execute("ALTER TABLE messages ADD COLUMN file_size INTEGER")
    
    c.execute("PRAGMA table_info(group_messages)")
    group_message_columns = [column[1] for column in c.fetchall()]
    if 'file_name' not in group_message_columns:
        c.execute("ALTER TABLE group_messages ADD COLUMN file_name TEXT")
    if 'file_size' not in group_message_columns:
        c.execute("ALTER TABLE group_messages ADD COLUMN file_size INTEGER")
    
    c.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in c.fetchall()]
    if 'status' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'Active'")
    if 'created_at' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN created_at TIMESTAMP")
        c.execute("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
    if 'profile_picture' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN profile_picture TEXT")
    
    c.execute('''
        UPDATE group_members 
        SET role = 'creator' 
        WHERE user_id IN (
            SELECT g.creator_id 
            FROM groups g 
            WHERE g.id = group_members.group_id
        ) AND role = 'admin'
    ''')
    
    c.execute('CREATE INDEX IF NOT EXISTS idx_messages_sender_receiver ON messages(sender_id, receiver_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_friend_requests_receiver ON friend_requests(receiver_id, status)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_group_members_group_user ON group_members(group_id, user_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_file_uploads_uploader ON file_uploads(uploader_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_file_uploads_filename ON file_uploads(filename)')
    
    conn.commit()
    conn.close()

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    if not hashed:
        return False
    if len(hashed) == 64:  # SHA256 hash length
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest() == hashed
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except ValueError:
        return False

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(email, otp):
    if not EMAIL_CONFIG['sender_email'] or not EMAIL_CONFIG['sender_password']:
        return False
    try:
        server = smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port'])
        server.starttls()
        server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
        
        msg = MIMEMultipart()
        msg['From'] = EMAIL_CONFIG['sender_email']
        msg['To'] = email
        msg['Subject'] = "Verification Code"
        
        body = f"Your verification code is: {otp}\n\nThis code will expire in 10 minutes."
        msg.attach(MIMEText(body, 'plain'))
        
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def send_reset_otp_email(email, otp):
    return send_otp_email(email, otp)

def send_deletion_email(email, reason):
    if not EMAIL_CONFIG['sender_email'] or not EMAIL_CONFIG['sender_password']:
        print("Email configuration missing")
        return False
    
    try:
        server = smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port'])
        server.starttls()
        server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
        
        msg = MIMEMultipart()
        msg['From'] = EMAIL_CONFIG['sender_email']
        msg['To'] = email
        msg['Subject'] = "Account Deletion Notification"
        
        body = f"""Dear User,

Your account has been deleted by an administrator.

Reason: {reason}

If you believe this was a mistake, please contact our support team.

Thank you,
The Support Team
"""
        msg.attach(MIMEText(body, 'plain'))
        
        server.send_message(msg)
        server.quit()
        print(f"Deletion email sent to {email}")
        return True
    except Exception as e:
        print(f"Deletion email error: {e}")
        return False

def detect_and_send_deletion_email(user_email, reason="Account violation"):
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('SELECT id, email, username FROM users WHERE email=?', (user_email,))
    user = c.fetchone()
    
    if not user:
        conn.close()
        return False, "User not found"
    
    if send_deletion_email(user_email, reason):
        user_id = user[0]
        c.execute('DELETE FROM users WHERE id=?', (user_id,))
        c.execute('DELETE FROM login_logs WHERE user_id=?', (user_id,))
        c.execute('DELETE FROM friend_requests WHERE sender_id=? OR receiver_id=?', (user_id, user_id))
        c.execute('DELETE FROM messages WHERE sender_id=? OR receiver_id=?', (user_id, user_id))
        c.execute('DELETE FROM group_members WHERE user_id=?', (user_id,))
        c.execute('DELETE FROM group_messages WHERE sender_id=?', (user_id,))
        c.execute('DELETE FROM file_uploads WHERE uploader_id=?', (user_id,))
        # Delete groups created by user
        c.execute('SELECT id FROM groups WHERE creator_id=?', (user_id,))
        user_groups = c.fetchall()
        for group in user_groups:
            group_id = group[0]
            c.execute('DELETE FROM group_messages WHERE group_id=?', (group_id,))
            c.execute('DELETE FROM group_members WHERE group_id=?', (group_id,))
        c.execute('DELETE FROM groups WHERE creator_id=?', (user_id,))
        conn.commit()
        conn.close()
        return True, "Deletion email sent and account deleted successfully"
    else:
        conn.close()
        return False, "Failed to send deletion email"

def read_settings() -> dict:
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('SELECT key, value FROM settings')
    rows = c.fetchall()
    conn.close()
    return {k: v for k, v in rows}

def save_settings(updates: dict):
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    for k, v in updates.items():
        c.execute('INSERT INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP', (k, str(v)))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('login_and_register.html')

@app.route('/favicon.ico')
def favicon():
    icon_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'images')
    return send_from_directory(icon_dir, 'logo.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/login', methods=['POST'])
def login_submit():
    # Handle both email and username fields for compatibility
    login_input = request.form.get('email') or request.form.get('username')
    password = request.form['password']
    
    if not login_input or not password:
        flash('Username/email and password are required')
        return redirect(url_for('index'))
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if login input is email or username
    if '@' in login_input:
        # It's an email
        c.execute('SELECT id, username, password, verified, status FROM users WHERE email=?', (login_input,))
    else:
        # It's a username
        c.execute('SELECT id, username, password, verified, status FROM users WHERE username=?', (login_input,))
    
    user = c.fetchone()
    
    if user and verify_password(password, user[2]):
        # Check if account is suspended or inactive
        if user[4] == 'Suspended':
            conn.close()
            flash('Your account has been suspended. Please contact support.')
            return redirect(url_for('index'))
        
        if user[4] == 'Inactive':
            conn.close()
            flash('Your account is inactive. Please contact support to reactivate.')
            return redirect(url_for('index'))
        
        if user[3] == 0:  # Check if verified - this should never happen now
            conn.close()
            flash('Account not verified. Please complete registration.')
            return redirect(url_for('index'))
        
        # Migrate old SHA256 password to bcrypt
        if len(user[2]) == 64:  # SHA256 hash
            new_hash = hash_password(password)
            c.execute('UPDATE users SET password=? WHERE id=?', (new_hash, user[0]))
            conn.commit()
        
        # Record login log before closing connection
        try:
            c.execute('INSERT OR IGNORE INTO login_logs (user_id, login_date) VALUES (?, DATE("now"))', (user[0],))
            conn.commit()
        except Exception as e:
            print(f"login_logs insert error: {e}")

        conn.close()

        session.permanent = True
        session['user_id'] = user[0]
        session['username'] = user[1]
        session['login_time'] = datetime.now().isoformat()

        return redirect(url_for('dashboard'))
    else:
        conn.close()
        flash('Invalid username/email or password')
        return redirect(url_for('index'))

@app.route('/register')
def register():
    return redirect(url_for('index'))

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login_page():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and password == 'admin':
            session['admin'] = True
            conn = sqlite3.connect(get_db_path())
            c = conn.cursor()
            c.execute('SELECT id, username, email FROM users')
            users = c.fetchall()
            conn.close()
            return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials')
    return render_template('admin_login.html')

@app.route('/admin')
def admin_dashboard():
    if 'admin' not in session:
        return redirect(url_for('admin_login_page'))
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('SELECT id, username, email, status FROM users')
    users = c.fetchall()
    c.execute('SELECT id, name, email, subject, message, created_at FROM contact_messages ORDER BY created_at DESC')
    messages = c.fetchall()
    c.execute('SELECT id, name, description, creator_id, created_at FROM groups ORDER BY created_at DESC')
    groups = c.fetchall()
    conn.close()
    return render_template('admin.html', users=users, messages=messages, groups=groups)

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        c.execute('INSERT INTO contact_messages (name, email, subject, message) VALUES (?, ?, ?, ?)',
                  (name, email, subject, message))
        conn.commit()
        conn.close()
        
        flash('Message sent successfully!')
        return redirect(url_for('contact'))
    return render_template('contact.html')

@app.route('/dashboard')
@app.route('/dashboard/<int:count>')
def dashboard(count=None):
    # Check if user is logged in
    if 'user_id' not in session or 'username' not in session:
        session.clear()
        flash('Please login to access dashboard')
        return redirect(url_for('index'))
    
    # Verify user still exists and credentials are valid
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('SELECT id, username, status, verified, profile_picture FROM users WHERE id=?', (session['user_id'],))
    user = c.fetchone()
    conn.close()
    
    # If user doesn't exist or session is invalid
    if not user:
        session.clear()
        flash('Invalid session. Please login again.')
        return redirect(url_for('index'))
    
    # Check if username in session matches database
    if user[1] != session['username']:
        session.clear()
        flash('Session mismatch. Please login again.')
        return redirect(url_for('index'))
    
    # Check account status
    if user[2] in ['Suspended', 'Inactive']:
        session.clear()
        flash('Your account is not active. Please contact support.')
        return redirect(url_for('index'))
    
    # Check if account is verified
    if user[3] == 0:
        session.clear()
        flash('Account not verified. Please complete registration.')
        return redirect(url_for('index'))
    
    # Use user_id as count if not provided
    if count is None:
        count = session['user_id']
    
    # Profile picture is loaded via API, not stored in session
    
    return render_template('dashboard.html', username=session['username'], user_number=count)

@app.route('/register', methods=['POST'])
def register_user():
    try:
        username = request.form.get('name') or request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([username, email, password, confirm_password]):
            return jsonify({'success': False, 'message': 'All fields are required'})
        
        is_valid, message = validate_password(password)
        if not is_valid:
            return jsonify({'success': False, 'message': message})
        
        if password != confirm_password:
            return jsonify({'success': False, 'message': 'Passwords do not match'})
        
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        
        c.execute('SELECT email FROM users WHERE username=? OR email=?', (username, email))
        if c.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Username or email already exists'})
        
        otp = generate_otp()
        expires_at = datetime.now() + timedelta(minutes=10)
        
        c.execute('DELETE FROM otp_codes WHERE email=?', (email,))
        c.execute('INSERT INTO otp_codes (email, otp, expires_at) VALUES (?, ?, ?)', 
                  (email, otp, expires_at.isoformat()))
        conn.commit()
        
        if send_otp_email(email, otp):
            session['pending_user'] = {
                'username': username,
                'email': email,
                'password': hash_password(password)
            }
            conn.close()
            return jsonify({'success': True, 'message': 'Verification code sent to your email', 'requires_otp': True})
        else:
            conn.close()
            return jsonify({'success': False, 'message': 'Failed to send verification code. Please try again.'})
            
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({'success': False, 'message': 'Registration failed. Please try again.'})


    
def send_update_notification_email(email, username, changes):
    """
    Send account update notification email
    """
    if not EMAIL_CONFIG['sender_email'] or not EMAIL_CONFIG['sender_password']:
        print("Email configuration missing")
        return False
    
    try:
        server = smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port'])
        server.starttls()
        server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
        
        msg = MIMEMultipart()
        msg['From'] = EMAIL_CONFIG['sender_email']
        msg['To'] = email
        msg['Subject'] = "Account Information Updated"
        
        # Create a detailed message about the changes
        changes_text = "\n".join([f"- {change}" for change in changes])
        
        body = f"""Dear {username},

Your account information has been updated by an administrator.

The following changes were made:
{changes_text}

If you did not request these changes or believe this was a mistake, please contact our support team immediately.

Thank you,
The Support Team
"""
        msg.attach(MIMEText(body, 'plain'))
        
        server.send_message(msg)
        server.quit()
        print(f"Update notification email sent to {email}")
        return True
    except Exception as e:
        print(f"Update notification email error: {e}")
        return False

@app.route('/admin/update-user', methods=['POST'])
def update_user():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    try:
        user_id = request.form.get('id')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        status = request.form.get('status')
        
        if not user_id or not username or not email or not status:
            return jsonify({'success': False, 'message': 'Missing required fields'})
        
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        
        # Get current user data to compare changes
        c.execute('SELECT username, email, status FROM users WHERE id=?', (user_id,))
        current_user = c.fetchone()
        
        if not current_user:
            conn.close()
            return jsonify({'success': False, 'message': 'User not found'})
        
        current_username, current_email, current_status = current_user
        changes = []
        
        # Check for username change
        if current_username != username:
            changes.append(f"Username changed from '{current_username}' to '{username}'")
        
        # Check for email change
        if current_email != email:
            changes.append(f"Email changed from '{current_email}' to '{email}'")
        
        # Check for status change
        if current_status != status:
            changes.append(f"Status changed from '{current_status}' to '{status}'")
        
        # Check if email is already taken by another user
        c.execute('SELECT id FROM users WHERE email=? AND id!=?', (email, user_id))
        if c.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Email already taken by another user'})
        
        # Check if username is already taken by another user
        c.execute('SELECT id FROM users WHERE username=? AND id!=?', (username, user_id))
        if c.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Username already taken by another user'})
        
        # Update user information
        if password:
            # Update with new password
            hashed_password = hash_password(password)
            c.execute('UPDATE users SET username=?, email=?, password=?, status=? WHERE id=?', 
                     (username, email, hashed_password, status, user_id))
            changes.append("Password was reset")
        else:
            # Update without changing password
            c.execute('UPDATE users SET username=?, email=?, status=? WHERE id=?', 
                     (username, email, status, user_id))
        
        conn.commit()
        conn.close()
        
        # Send notification email if there were changes
        if changes:
            # Use the new email if it was changed, otherwise use the current email
            notification_email = email if current_email != email else current_email
            send_update_notification_email(notification_email, username, changes)
        
        return jsonify({'success': True, 'message': 'User updated successfully'})
    
    except Exception as e:
        print(f"Error updating user: {e}")
        return jsonify({'success': False, 'message': 'Error updating user'})

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    otp = data.get('otp')
    email = data.get('email')
    
    if 'pending_user' not in session:
        return jsonify({'success': False, 'message': 'Session expired. Please register again.'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('SELECT otp, expires_at FROM otp_codes WHERE email=? ORDER BY created_at DESC LIMIT 1', (email,))
    otp_record = c.fetchone()
    
    if not otp_record:
        conn.close()
        session.pop('pending_user', None)  # Clear session on invalid OTP
        return jsonify({'success': False, 'message': 'Invalid OTP. Please register again.'})
    
    stored_otp, expires_at = otp_record
    if datetime.now() > datetime.fromisoformat(expires_at):
        conn.close()
        session.pop('pending_user', None)  # Clear session on expired OTP
        return jsonify({'success': False, 'message': 'OTP expired. Please register again.'})
    
    if otp != stored_otp:
        conn.close()
        return jsonify({'success': False, 'message': 'Invalid OTP. Please try again.'})
    
    # OTP is valid, create user account
    pending_user = session['pending_user']
    c.execute('INSERT INTO users (username, email, password, verified, created_at) VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)',
              (pending_user['username'], pending_user['email'], pending_user['password']))
    c.execute('DELETE FROM otp_codes WHERE email=?', (email,))
    conn.commit()
    conn.close()
    
    session.pop('pending_user', None)
    return jsonify({'success': True, 'message': 'Account created successfully! You can now login.'})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Socket.IO events
@socketio.on('connect')
def handle_connect():
    user_id = session.get('user_id')
    if user_id:
        join_room(str(user_id))
        emit('connected', {'user_id': user_id})
        try:
            ONLINE_USERS.add(user_id)
            socketio.emit('presence', {'online': len(ONLINE_USERS)})
        except Exception:
            pass

@socketio.on('disconnect')
def handle_disconnect():
    user_id = session.get('user_id')
    if user_id:
        leave_room(str(user_id))
        try:
            if user_id in ONLINE_USERS:
                ONLINE_USERS.remove(user_id)
                socketio.emit('presence', {'online': len(ONLINE_USERS)})
        except Exception:
            pass

@socketio.on('send_message')
def handle_send_message(data):
    sender_id = session.get('user_id')
    receiver_id = data.get('to')
    content = data.get('content')
    message_type = data.get('message_type', 'text')
    file_url = data.get('file_url')
    file_name = data.get('file_name')
    file_size = data.get('file_size')
    
    if not sender_id or not receiver_id or (not content and not file_url):
        return
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if receiver has blocked sender OR sender has blocked receiver
    c.execute('SELECT 1 FROM blocked_users WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)', 
              (receiver_id, sender_id, sender_id, receiver_id))
    if c.fetchone():
        conn.close()
        emit('message_blocked', {'message': 'Message not delivered due to blocking'}, to=str(sender_id))
        return
    
    # Validate file access if file is being shared
    if file_url and message_type == 'file':
        filename = os.path.basename(file_url)
        c.execute('SELECT uploader_id FROM file_uploads WHERE filename = ?', (filename,))
        file_result = c.fetchone()
        
        if not file_result or file_result[0] != sender_id:
            conn.close()
            emit('error', {'message': 'File access denied'}, to=str(sender_id))
            return
    
    c.execute('''
        INSERT INTO messages (sender_id, receiver_id, content, message_type, file_url, file_name, file_size) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (sender_id, receiver_id, content or '', message_type, file_url, file_name, file_size))
    conn.commit()
    message_id = c.lastrowid
    c.execute('SELECT created_at FROM messages WHERE id=?', (message_id,))
    row = c.fetchone()
    created_at = row[0] if row else None
    conn.close()
    
    payload = {
        'id': message_id, 
        'from': sender_id, 
        'to': receiver_id, 
        'content': content or '', 
        'message_type': message_type,
        'file_url': file_url,
        'file_name': file_name,
        'file_size': file_size,
        'created_at': created_at
    }
    emit('new_message', payload, to=str(receiver_id))
    try:
        socketio.emit('unseen_update', {'from': sender_id}, to=str(receiver_id))
    except Exception:
        pass
    emit('new_message', payload, to=str(sender_id))

@socketio.on('send_group_message')
def handle_send_group_message(data):
    sender_id = session.get('user_id')
    group_id = data.get('group_id')
    content = data.get('content')
    message_type = data.get('message_type', 'text')
    file_url = data.get('file_url')
    file_name = data.get('file_name')
    file_size = data.get('file_size')
    
    if not sender_id or not group_id or (not content and not file_url):
        return
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if user is a member of the group
    c.execute('SELECT id FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, sender_id))
    if not c.fetchone():
        conn.close()
        emit('error', {'message': 'Not a member of this group'}, to=str(sender_id))
        return
    
    # Validate file access if file is being shared
    if file_url and message_type == 'file':
        filename = os.path.basename(file_url)
        c.execute('SELECT uploader_id FROM file_uploads WHERE filename = ?', (filename,))
        file_result = c.fetchone()
        
        if not file_result or file_result[0] != sender_id:
            conn.close()
            emit('error', {'message': 'File access denied'}, to=str(sender_id))
            return
    
    # Insert group message
    c.execute('''
        INSERT INTO group_messages (group_id, sender_id, content, message_type, file_url) 
        VALUES (?, ?, ?, ?, ?)
    ''', (group_id, sender_id, content or '', message_type, file_url))
    conn.commit()
    message_id = c.lastrowid
    
    # Get sender info
    c.execute('SELECT username FROM users WHERE id = ?', (sender_id,))
    sender_name = c.fetchone()[0]
    
    # Get all group members
    c.execute('SELECT user_id FROM group_members WHERE group_id = ?', (group_id,))
    members = c.fetchall()
    
    conn.close()
    
    payload = {
        'id': message_id,
        'group_id': group_id,
        'sender_id': sender_id,
        'sender_name': sender_name,
        'content': content or '',
        'message_type': message_type,
        'file_url': file_url,
        'file_name': file_name,
        'file_size': file_size,
        'created_at': datetime.now().isoformat()
    }
    
    # Emit to all group members
    for member in members:
        emit('new_group_message', payload, to=str(member[0]))

# WebRTC signaling for voice/video calls
@socketio.on('call_user')
def handle_call_user(data):
    caller_id = session.get('user_id')
    callee_id = data.get('user_id')
    call_type = data.get('call_type', 'audio')  # 'audio' or 'video'
    
    if not caller_id or not callee_id:
        return
    
    # Get caller info
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('SELECT username FROM users WHERE id = ?', (caller_id,))
    result = c.fetchone()
    caller_name = result[0] if result else 'Unknown'
    conn.close()
    
    emit('incoming_call', {
        'caller_id': caller_id,
        'caller_name': caller_name,
        'call_type': call_type
    }, to=str(callee_id))

@socketio.on('answer_call')
def handle_answer_call(data):
    caller_id = data.get('caller_id')
    answer = data.get('answer')  # True for accept, False for reject
    
    if caller_id:
        emit('call_answered', {
            'answer': answer,
            'answerer_id': session.get('user_id')
        }, to=str(caller_id))

@socketio.on('webrtc_signal')
def handle_webrtc_signal(data):
    target_id = data.get('target_id')
    signal_data = data.get('signal')
    
    if target_id and signal_data:
        emit('webrtc_signal', {
            'signal': signal_data,
            'sender_id': session.get('user_id')
        }, to=str(target_id))

@socketio.on('end_call')
def handle_end_call(data):
    target_id = data.get('target_id')
    
    if target_id:
        emit('call_ended', {
            'ended_by': session.get('user_id')
        }, to=str(target_id))

@app.route('/about/stats')
def about_stats():
    try:
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM users')
        total_users = c.fetchone()[0]
        try:
            c.execute('SELECT COUNT(*) FROM messages')
            total_messages = c.fetchone()[0]
        except Exception:
            total_messages = 0
        conn.close()
    except Exception:
        total_users = 0
        total_messages = 0
    # Countries static example; highlight Pakistan as requested
    countries = ['Pakistan']
    uptime = '99.9%'
    return jsonify({
        'success': True,
        'stats': {
            'active_users': len(ONLINE_USERS),
            'total_users': total_users,
            'messages_sent': total_messages,
            'countries': countries,
            'uptime': uptime
        }
    })

@app.route('/messages/unseen')
def messages_unseen():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    my_id = session['user_id']
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    try:
        c.execute('''
            SELECT COUNT(*) FROM messages m 
            WHERE m.receiver_id=? AND m.seen=0 
            AND m.id NOT IN (SELECT dm.message_id FROM deleted_messages dm WHERE dm.user_id=?)
        ''', (my_id, my_id))
        total = c.fetchone()[0]
        c.execute('''
            SELECT m.sender_id, COUNT(*) FROM messages m 
            WHERE m.receiver_id=? AND m.seen=0 
            AND m.id NOT IN (SELECT dm.message_id FROM deleted_messages dm WHERE dm.user_id=?)
            GROUP BY m.sender_id
        ''', (my_id, my_id))
        per = c.fetchall()
    except Exception:
        total = 0
        per = []
    conn.close()
    return jsonify({'success': True, 'total': total, 'by_friend': per})

@app.route('/messages/mark-seen', methods=['POST'])
def messages_mark_seen():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    data = request.get_json() if request.is_json else request.form
    other_id = data.get('other_id')
    if not other_id:
        return jsonify({'success': False, 'message': 'other_id is required'}), 400
    try:
        other_id = int(other_id)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid other_id'}), 400
    my_id = session['user_id']
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('UPDATE messages SET seen=1 WHERE receiver_id=? AND sender_id=? AND seen=0', (my_id, other_id))
    conn.commit()
    conn.close()
    try:
        socketio.emit('unseen_update', {'from': other_id}, to=str(my_id))
    except Exception:
        pass
    return jsonify({'success': True})

@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    data = request.get_json()
    email = data.get('email')
    
    if 'pending_user' not in session:
        return jsonify({'success': False, 'message': 'Session expired. Please register again.'})
    
    # Generate new OTP
    otp = generate_otp()
    expires_at = datetime.now() + timedelta(minutes=10)
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('DELETE FROM otp_codes WHERE email=?', (email,))
    c.execute('INSERT INTO otp_codes (email, otp, expires_at) VALUES (?, ?, ?)', 
              (email, otp, expires_at.isoformat()))
    conn.commit()
    conn.close()
    
    if send_otp_email(email, otp):
        return jsonify({'success': True, 'message': 'New verification code sent successfully'})
    else:
        return jsonify({'success': False, 'message': 'Failed to send verification code. Please try again.'})

@app.route('/forgot-password')
def forgot_password_page():
    return render_template('forget_password.html')

@app.route('/verify-reset-otp')
def verify_reset_otp_page():
    return render_template('verify_reset_otp.html')

@app.route('/verify-otp-page')
def verify_otp_page():
    return render_template('verify_otp.html')

@app.route('/reset-password')
def reset_password_page():
    return render_template('reset_password.html')

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json() if request.is_json else request.form
    email = data.get('email')
    
    if not email:
        return jsonify({'success': False, 'message': 'Email is required'})
    
    # Check if user exists
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE email=?', (email,))
    user = c.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'success': False, 'message': 'No account found with this email address'})
    
    # Generate and send OTP
    otp = generate_otp()
    expires_at = datetime.now() + timedelta(minutes=10)
    
    # Store OTP for password reset
    c.execute('DELETE FROM otp_codes WHERE email=?', (email,))
    c.execute('INSERT INTO otp_codes (email, otp, expires_at) VALUES (?, ?, ?)', 
              (email, otp, expires_at.isoformat()))
    conn.commit()
    conn.close()
    
    if send_reset_otp_email(email, otp):
        return jsonify({'success': True, 'message': 'Verification code sent to your email'})
    else:
        return jsonify({'success': False, 'message': 'Failed to send verification code. Please try again.'})

@app.route('/verify-reset-otp', methods=['POST'])
def verify_reset_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    
    if not email or not otp:
        return jsonify({'success': False, 'message': 'Email and OTP are required'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('SELECT otp, expires_at FROM otp_codes WHERE email=? ORDER BY created_at DESC LIMIT 1', (email,))
    otp_record = c.fetchone()
    conn.close()
    
    if not otp_record:
        return jsonify({'success': False, 'message': 'Invalid verification code'})
    
    stored_otp, expires_at = otp_record
    if datetime.now() > datetime.fromisoformat(expires_at):
        return jsonify({'success': False, 'message': 'Verification code expired. Please request a new one.'})
    
    if otp != stored_otp:
        return jsonify({'success': False, 'message': 'Invalid verification code'})
    
    # Store verified email in session for password reset
    session['reset_email'] = email
    return jsonify({'success': True, 'message': 'Code verified successfully'})

@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    new_password = data.get('newPassword')
    
    # Verify session
    if 'reset_email' not in session or session['reset_email'] != email:
        return jsonify({'success': False, 'message': 'Invalid session. Please start the reset process again.'})
    
    if not new_password:
        return jsonify({'success': False, 'message': 'New password is required'})
    
    # Validate password
    is_valid, message = validate_password(new_password)
    if not is_valid:
        return jsonify({'success': False, 'message': message})
    
    # Update password
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    hashed_password = hash_password(new_password)
    c.execute('UPDATE users SET password=? WHERE email=?', (hashed_password, email))
    
    # Clean up OTP codes
    c.execute('DELETE FROM otp_codes WHERE email=?', (email,))
    conn.commit()
    conn.close()
    
    # Clear session
    session.pop('reset_email', None)
    
    return jsonify({'success': True, 'message': 'Password reset successfully'})

@app.route('/resend-reset-otp', methods=['POST'])
def resend_reset_otp():
    data = request.get_json()
    email = data.get('email')
    
    if not email:
        return jsonify({'success': False, 'message': 'Email is required'})
    
    # Check if user exists
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE email=?', (email,))
    user = c.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'success': False, 'message': 'No account found with this email address'})
    
    # Generate new OTP
    otp = generate_otp()
    expires_at = datetime.now() + timedelta(minutes=10)
    
    c.execute('DELETE FROM otp_codes WHERE email=?', (email,))
    c.execute('INSERT INTO otp_codes (email, otp, expires_at) VALUES (?, ?, ?)', 
              (email, otp, expires_at.isoformat()))
    conn.commit()
    conn.close()
    
    if send_reset_otp_email(email, otp):
        return jsonify({'success': True, 'message': 'Verification code resent successfully'})
    else:
        return jsonify({'success': False, 'message': 'Failed to resend verification code. Please try again.'})

@app.route('/auth/google')
def google_login():
    # CSRF protection using state
    state_token = secrets.token_urlsafe(32)
    session['oauth_state'] = state_token

    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid email profile',
        'access_type': 'offline',
        'prompt': 'consent',
        'include_granted_scopes': 'true',
        'state': state_token,
    }
    auth_base = 'https://accounts.google.com/o/oauth2/v2/auth'
    auth_url = f"{auth_base}?{urlencode(params)}"
    return redirect(auth_url)

@app.route('/auth/google/callback')
def google_callback():
    code = request.args.get('code')
    state_param = request.args.get('state')
    expected_state = session.pop('oauth_state', None)
    if not expected_state or state_param != expected_state:
        flash('Google login failed: invalid state')
        return redirect(url_for('index'))
    if not code:
        flash('Google login failed')
        return redirect(url_for('index'))
    try:
        token_data = {
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': GOOGLE_REDIRECT_URI
        }
        token_response = requests.post('https://oauth2.googleapis.com/token', data=token_data, timeout=10)
        token_response.raise_for_status()
        token_json = token_response.json()
        token = token_json.get('access_token')
        if token:
            user_response = requests.get(
                'https://openidconnect.googleapis.com/v1/userinfo',
                headers={'Authorization': f'Bearer {token}'},
                timeout=10
            )
            user_response.raise_for_status()
            user_info = user_response.json()
            if 'email' in user_info:
                email = user_info['email']
                full_name = user_info.get('name')
                conn = sqlite3.connect(get_db_path())
                c = conn.cursor()
                c.execute('SELECT id, username FROM users WHERE email=?', (email,))
                user = c.fetchone()
                if user:
                    # log login
                    try:
                        c.execute('INSERT OR IGNORE INTO login_logs (user_id, login_date) VALUES (?, DATE("now"))', (user[0],))
                        conn.commit()
                    except Exception as e:
                        print(f"login_logs insert error: {e}")
                    session.permanent = True
                    session['user_id'] = user[0]
                    session['username'] = user[1]
                    conn.close()
                    return redirect(url_for('dashboard', count=session['user_id']))
                else:
                    # Auto-create a new user for first-time Google login
                    # Derive a username from email local part and ensure uniqueness
                    base_username = email.split('@')[0]
                    candidate_username = base_username
                    suffix = 1
                    c.execute('SELECT 1 FROM users WHERE username=?', (candidate_username,))
                    while c.fetchone():
                        suffix += 1
                        candidate_username = f"{base_username}{suffix}"
                        c.execute('SELECT 1 FROM users WHERE username=?', (candidate_username,))

                    c.execute(
                        'INSERT INTO users (username, email, password, verified, created_at) VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)',
                        (candidate_username, email, None)
                    )
                    conn.commit()
                    c.execute('SELECT id FROM users WHERE email=?', (email,))
                    new_user = c.fetchone()
                    if new_user:
                        # log login
                        try:
                            c.execute('INSERT OR IGNORE INTO login_logs (user_id, login_date) VALUES (?, DATE("now"))', (new_user[0],))
                            conn.commit()
                        except Exception as e:
                            print(f"login_logs insert error: {e}")
                        conn.close()
                        session.permanent = True
                        session['user_id'] = new_user[0]
                        session['username'] = candidate_username
                        return redirect(url_for('dashboard', count=session['user_id']))
                    else:
                        conn.close()
                        flash('Google login failed while creating account')
                        return redirect(url_for('index'))
        flash('Google login failed')
        return redirect(url_for('index'))
    except Exception as e:
        print(f"Google OAuth error: {e}")
        flash('Google login failed')
        return redirect(url_for('index'))

@app.route('/send-friend-request', methods=['POST'])
def send_friend_request():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'})
    
    data = request.get_json()
    username = data.get('username')
    
    if not username:
        return jsonify({'success': False, 'message': 'Username is required'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    c.execute('SELECT id FROM users WHERE username=?', (username,))
    receiver = c.fetchone()
    
    if not receiver:
        conn.close()
        return jsonify({'success': False, 'message': 'User not found'})
    
    receiver_id = receiver[0]
    sender_id = session['user_id']
    
    if sender_id == receiver_id:
        conn.close()
        return jsonify({'success': False, 'message': 'Cannot send friend request to yourself'})
    
    c.execute('SELECT status FROM friend_requests WHERE sender_id=? AND receiver_id=?', (sender_id, receiver_id))
    existing = c.fetchone()
    
    if existing:
        conn.close()
        return jsonify({'success': False, 'message': 'Friend request already sent'})
    
    c.execute('INSERT INTO friend_requests (sender_id, receiver_id) VALUES (?, ?)', (sender_id, receiver_id))
    conn.commit()
    try:
        socketio.emit('friend_request', {'from_user_id': sender_id, 'to_user_id': receiver_id}, to=str(receiver_id))
    except Exception as e:
        print(f"socket emit error: {e}")
    conn.close()
    
    return jsonify({'success': True, 'message': 'Friend request sent successfully'})

@app.route('/get-friend-requests')
def get_friend_requests():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    c.execute('''SELECT fr.id, u.username, fr.created_at 
                 FROM friend_requests fr 
                 JOIN users u ON fr.sender_id = u.id 
                 WHERE fr.receiver_id=? AND fr.status="pending"''', (session['user_id'],))
    requests = c.fetchall()
    conn.close()
    
    return jsonify({'success': True, 'requests': requests})

@app.route('/friends/list')
def friends_list():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    me = session['user_id']
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    # Get accepted friendships and resolve the other user id, then join for username/email
    c.execute('''
        SELECT u.id, u.username, u.email
        FROM (
            SELECT CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END AS friend_id
            FROM friend_requests
            WHERE (sender_id = ? OR receiver_id = ?) AND status = 'accepted'
        ) f
        JOIN users u ON u.id = f.friend_id
        ORDER BY u.username COLLATE NOCASE ASC
    ''', (me, me, me))
    friends = c.fetchall()
    conn.close()
    return jsonify({'success': True, 'friends': friends})

@app.route('/friends/accepted')
def friends_accepted():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    me = session['user_id']
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('''
        SELECT u.id, u.username, u.profile_picture
        FROM (
            SELECT CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END AS friend_id
            FROM friend_requests
            WHERE (sender_id = ? OR receiver_id = ?) AND status = 'accepted'
        ) f
        JOIN users u ON u.id = f.friend_id
        ORDER BY u.username COLLATE NOCASE ASC
    ''', (me, me, me))
    friends = c.fetchall()
    
    # Add online status and unread count to friends
    friends_with_status = []
    for friend in friends:
        is_online = friend[0] in ONLINE_USERS
        # Get unread count from this friend
        c.execute('''
            SELECT COUNT(*) FROM messages m 
            WHERE m.sender_id=? AND m.receiver_id=? AND m.seen=0 
            AND m.id NOT IN (SELECT dm.message_id FROM deleted_messages dm WHERE dm.user_id=?)
        ''', (friend[0], me, me))
        unread_count = c.fetchone()[0]
        friends_with_status.append([friend[0], friend[1], is_online, friend[2], unread_count])  # id, username, online, profile_picture, unread
    
    conn.close()
    return jsonify({'success': True, 'friends': friends_with_status})

@app.route('/friends/for-group/<int:group_id>')
def friends_for_group(group_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    me = session['user_id']
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if user is a member of the group
    c.execute('SELECT role FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, me))
    member = c.fetchone()
    if not member:
        conn.close()
        return jsonify({'success': False, 'message': 'Not a member of this group'}), 403
    
    # Get friends who are not already in the group
    c.execute('''
        SELECT u.id, u.username, u.profile_picture
        FROM (
            SELECT CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END AS friend_id
            FROM friend_requests
            WHERE (sender_id = ? OR receiver_id = ?) AND status = 'accepted'
        ) f
        JOIN users u ON u.id = f.friend_id
        WHERE u.id NOT IN (
            SELECT user_id FROM group_members WHERE group_id = ?
        )
        ORDER BY u.username COLLATE NOCASE ASC
    ''', (me, me, me, group_id))
    
    friends = c.fetchall()
    conn.close()
    
    return jsonify({
        'success': True, 
        'friends': [{
            'id': f[0],
            'username': f[1],
            'profile_picture': f[2]
        } for f in friends]
    })

@app.route('/users/resolve')
def resolve_user():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    username = request.args.get('username')
    if not username:
        return jsonify({'success': False, 'message': 'Username is required'}), 400
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('SELECT id, username, email FROM users WHERE username=?', (username,))
    user = c.fetchone()
    conn.close()
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    return jsonify({'success': True, 'user': {'id': user[0], 'username': user[1], 'email': user[2]}})

@app.route('/messages/history')
def messages_history():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    try:
        other_id = int(request.args.get('with_user_id', '0'))
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid user id'}), 400
    if not other_id:
        return jsonify({'success': False, 'message': 'with_user_id is required'}), 400
    my_id = session['user_id']
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('''
        SELECT m.id, m.sender_id, m.receiver_id, m.content, m.created_at, m.message_type, m.file_url, m.file_name, m.file_size
        FROM messages m
        WHERE ((m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?))
        AND m.id NOT IN (
            SELECT dm.message_id FROM deleted_messages dm WHERE dm.user_id=?
        )
        ORDER BY m.created_at ASC
    ''', (my_id, other_id, other_id, my_id, my_id))
    rows = c.fetchall()
    conn.close()
    
    # Format messages with file info
    formatted_messages = []
    for row in rows:
        msg = {
            'id': row[0],
            'sender_id': row[1], 
            'receiver_id': row[2],
            'content': row[3],
            'created_at': row[4],
            'message_type': row[5] if len(row) > 5 else 'text',
            'file_url': row[6] if len(row) > 6 else None,
            'file_name': row[7] if len(row) > 7 else None,
            'file_size': row[8] if len(row) > 8 else None
        }
        formatted_messages.append(msg)
    
    return jsonify({'success': True, 'messages': formatted_messages})

@app.route('/messages/stats')
def messages_stats():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    my_id = session['user_id']
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    try:
        c.execute('SELECT COUNT(*) FROM messages WHERE sender_id=?', (my_id,))
        sent = c.fetchone()[0]
    except Exception:
        sent = 0
    try:
        c.execute('SELECT COUNT(*) FROM messages WHERE receiver_id=?', (my_id,))
        received = c.fetchone()[0]
    except Exception:
        received = 0
    conn.close()
    return jsonify({'success': True, 'sent': sent, 'received': received})

@app.route('/messages/clear', methods=['POST'])
def clear_messages():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json() if request.is_json else request.form
    other_user_id = data.get('other_user_id')
    
    if not other_user_id:
        return jsonify({'success': False, 'message': 'other_user_id is required'}), 400
    
    try:
        other_user_id = int(other_user_id)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid other_user_id'}), 400
    
    my_id = session['user_id']
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Get all message IDs between the two users
    c.execute('SELECT id FROM messages WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)', 
              (my_id, other_user_id, other_user_id, my_id))
    message_ids = [row[0] for row in c.fetchall()]
    
    # Mark messages as deleted for current user only
    for msg_id in message_ids:
        c.execute('INSERT OR IGNORE INTO deleted_messages (user_id, message_id) VALUES (?, ?)', 
                  (my_id, msg_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': f'Cleared {len(message_ids)} messages for you', 'deleted_count': len(message_ids)})

@app.route('/messages/delete-for-everyone', methods=['POST'])
def delete_message_for_everyone():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json() if request.is_json else request.form
    message_id = data.get('message_id')
    
    if not message_id:
        return jsonify({'success': False, 'message': 'message_id is required'}), 400
    
    try:
        message_id = int(message_id)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid message_id'}), 400
    
    my_id = session['user_id']
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if message exists and user is the sender
    c.execute('SELECT sender_id, receiver_id, content FROM messages WHERE id=?', (message_id,))
    message = c.fetchone()
    
    if not message:
        conn.close()
        return jsonify({'success': False, 'message': 'Message not found'}), 404
    
    sender_id, receiver_id, content = message
    
    # Only allow sender to delete for everyone
    if sender_id != my_id:
        conn.close()
        return jsonify({'success': False, 'message': 'You can only delete your own messages for everyone'}), 403
    
    # Delete message from database completely
    c.execute('DELETE FROM messages WHERE id=?', (message_id,))
    # Also remove any deleted_messages entries for this message
    c.execute('DELETE FROM deleted_messages WHERE message_id=?', (message_id,))
    
    conn.commit()
    conn.close()
    
    # Notify both users that message was deleted
    try:
        socketio.emit('message_deleted_for_everyone', {
            'message_id': message_id,
            'deleted_by': my_id
        }, to=str(sender_id))
        socketio.emit('message_deleted_for_everyone', {
            'message_id': message_id,
            'deleted_by': my_id
        }, to=str(receiver_id))
    except Exception as e:
        print(f"Socket emit error: {e}")
    
    return jsonify({'success': True, 'message': 'Message deleted for everyone'})

@app.route('/messages/delete-for-me', methods=['POST'])
def delete_message_for_me():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json() if request.is_json else request.form
    message_id = data.get('message_id')
    
    if not message_id:
        return jsonify({'success': False, 'message': 'message_id is required'}), 400
    
    try:
        message_id = int(message_id)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid message_id'}), 400
    
    my_id = session['user_id']
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if message exists
    c.execute('SELECT id FROM messages WHERE id=?', (message_id,))
    if not c.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'Message not found'}), 404
    
    # Mark message as deleted for current user only
    c.execute('INSERT OR IGNORE INTO deleted_messages (user_id, message_id) VALUES (?, ?)', 
              (my_id, message_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Message deleted for you'})

@app.route('/users/block', methods=['POST'])
def block_user():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json() if request.is_json else request.form
    user_id = data.get('user_id')
    
    if not user_id:
        return jsonify({'success': False, 'message': 'user_id is required'}), 400
    
    try:
        user_id = int(user_id)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid user_id'}), 400
    
    my_id = session['user_id']
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Create blocked_users table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS blocked_users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  blocker_id INTEGER NOT NULL,
                  blocked_id INTEGER NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (blocker_id) REFERENCES users (id),
                  FOREIGN KEY (blocked_id) REFERENCES users (id),
                  UNIQUE(blocker_id, blocked_id))''')
    
    # Block user
    c.execute('INSERT OR IGNORE INTO blocked_users (blocker_id, blocked_id) VALUES (?, ?)', (my_id, user_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'User blocked successfully'})

@app.route('/users/unblock', methods=['POST'])
def unblock_user():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json() if request.is_json else request.form
    user_id = data.get('user_id')
    
    if not user_id:
        return jsonify({'success': False, 'message': 'user_id is required'}), 400
    
    try:
        user_id = int(user_id)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid user_id'}), 400
    
    my_id = session['user_id']
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Unblock user
    c.execute('DELETE FROM blocked_users WHERE blocker_id=? AND blocked_id=?', (my_id, user_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'User unblocked successfully'})

@app.route('/users/blocked-status')
def check_blocked_status():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'user_id is required'}), 400
    
    try:
        user_id = int(user_id)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid user_id'}), 400
    
    my_id = session['user_id']
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if user is blocked
    c.execute('SELECT 1 FROM blocked_users WHERE blocker_id=? AND blocked_id=?', (my_id, user_id))
    is_blocked = c.fetchone() is not None
    
    conn.close()
    
    return jsonify({'success': True, 'is_blocked': is_blocked})

# Groups functionality
@app.route('/groups/create', methods=['POST'])
def create_group():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json()
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    is_private = data.get('is_private', False)
    
    if not name:
        return jsonify({'success': False, 'message': 'Group name is required'})
    
    if len(name) > 50:
        return jsonify({'success': False, 'message': 'Group name must be 50 characters or less'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    try:
        # Create group
        c.execute('INSERT INTO groups (name, description, creator_id, is_private) VALUES (?, ?, ?, ?)',
                  (name, description, session['user_id'], 1 if is_private else 0))
        group_id = c.lastrowid
        
        # Add creator as creator member
        c.execute('INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)',
                  (group_id, session['user_id'], 'creator'))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True, 
            'message': 'Group created successfully',
            'group': {
                'id': group_id,
                'name': name,
                'description': description,
                'is_private': is_private
            }
        })
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': 'Failed to create group'})

@app.route('/groups/list')
def list_groups():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Get user's groups
    c.execute('''
        SELECT g.id, g.name, g.description, g.creator_id, g.created_at, g.is_private,
               u.username as creator_name, gm.role,
               COUNT(DISTINCT gm2.user_id) as member_count
        FROM groups g
        JOIN group_members gm ON g.id = gm.group_id
        JOIN users u ON g.creator_id = u.id
        LEFT JOIN group_members gm2 ON g.id = gm2.group_id
        WHERE gm.user_id = ?
        GROUP BY g.id, g.name, g.description, g.creator_id, g.created_at, g.is_private, u.username, gm.role
        ORDER BY g.created_at DESC
    ''', (session['user_id'],))
    
    groups = c.fetchall()
    conn.close()
    
    return jsonify({
        'success': True,
        'groups': [{
            'id': g[0],
            'name': g[1],
            'description': g[2],
            'creator_id': g[3],
            'created_at': g[4],
            'is_private': g[5],
            'creator_name': g[6],
            'user_role': g[7],
            'member_count': g[8]
        } for g in groups]
    })

@app.route('/groups/<int:group_id>/messages')
def get_group_messages(group_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if user is a member
    c.execute('SELECT id FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, session['user_id']))
    if not c.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'Not a member of this group'}), 403
    
    # Get messages with file info
    c.execute('''
        SELECT gm.id, gm.sender_id, gm.content, gm.message_type, gm.file_url, gm.created_at, u.username,
               gm.file_name, gm.file_size
        FROM group_messages gm
        JOIN users u ON gm.sender_id = u.id
        WHERE gm.group_id = ?
        ORDER BY gm.created_at ASC
        LIMIT 100
    ''', (group_id,))
    
    messages = c.fetchall()
    conn.close()
    
    return jsonify({
        'success': True,
        'messages': [{
            'id': m[0],
            'sender_id': m[1],
            'content': m[2],
            'message_type': m[3],
            'file_url': m[4],
            'created_at': m[5],
            'sender_name': m[6],
            'file_name': m[7] if len(m) > 7 else None,
            'file_size': m[8] if len(m) > 8 else None
        } for m in messages]
    })

@app.route('/groups/<int:group_id>/add-member', methods=['POST'])
def add_group_member(group_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json()
    friend_id = data.get('friend_id')
    
    if not friend_id:
        return jsonify({'success': False, 'message': 'Friend ID is required'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if current user is admin or creator of the group
    c.execute('SELECT creator_id, name FROM groups WHERE id = ?', (group_id,))
    group = c.fetchone()
    if not group:
        conn.close()
        return jsonify({'success': False, 'message': 'Group not found'})
    
    c.execute('SELECT role FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, session['user_id']))
    member = c.fetchone()
    
    if not member or (member[0] not in ['admin', 'creator'] and group[0] != session['user_id']):
        conn.close()
        return jsonify({'success': False, 'message': 'Only admins can add members'})
    
    # Check if they are friends
    c.execute('''
        SELECT 1 FROM friend_requests 
        WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)) 
        AND status = 'accepted'
    ''', (session['user_id'], friend_id, friend_id, session['user_id']))
    
    if not c.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'You can only add friends to groups'})
    
    # Check if user is already a member
    c.execute('SELECT id FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, friend_id))
    if c.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'User is already a member of this group'})
    
    # Get adder's username for notification
    c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
    adder_name = c.fetchone()[0]
    
    # Add member
    c.execute('INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)', 
              (group_id, friend_id, 'member'))
    conn.commit()
    conn.close()
    
    # Send notification to added friend
    try:
        socketio.emit('group_added', {
            'group_id': group_id,
            'group_name': group[1],
            'added_by': adder_name,
            'message': f'You have been added to the group "{group[1]}" by {adder_name}'
        }, to=str(friend_id))
    except Exception as e:
        print(f"Socket emit error: {e}")
    
    return jsonify({'success': True, 'message': 'Friend added to group successfully'})

@app.route('/groups/<int:group_id>/join', methods=['POST'])
def join_group(group_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if group exists and is not private
    c.execute('SELECT is_private FROM groups WHERE id = ?', (group_id,))
    group = c.fetchone()
    if not group:
        conn.close()
        return jsonify({'success': False, 'message': 'Group not found'})
    
    if group[0] == 1:  # Private group
        conn.close()
        return jsonify({'success': False, 'message': 'Cannot join private group'})
    
    # Check if already a member
    c.execute('SELECT id FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, session['user_id']))
    if c.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'Already a member of this group'})
    
    # Join group
    c.execute('INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)', 
              (group_id, session['user_id'], 'member'))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Joined group successfully'})

@app.route('/groups/<int:group_id>/leave', methods=['POST'])
def leave_group(group_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if user is a member
    c.execute('SELECT role FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, session['user_id']))
    member = c.fetchone()
    if not member:
        conn.close()
        return jsonify({'success': False, 'message': 'Not a member of this group'})
    
    # Remove from group
    c.execute('DELETE FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Left group successfully'})

@app.route('/groups/<int:group_id>/kick-member', methods=['POST'])
def kick_group_member(group_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json()
    member_id = data.get('member_id')
    
    if not member_id:
        return jsonify({'success': False, 'message': 'Member ID is required'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if current user is admin or creator
    c.execute('SELECT creator_id FROM groups WHERE id = ?', (group_id,))
    group = c.fetchone()
    if not group:
        conn.close()
        return jsonify({'success': False, 'message': 'Group not found'})
    
    c.execute('SELECT role FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, session['user_id']))
    current_member = c.fetchone()
    
    if not current_member or (current_member[0] not in ['admin', 'creator'] and group[0] != session['user_id']):
        conn.close()
        return jsonify({'success': False, 'message': 'Only admins can kick members'})
    
    # Check target member's role
    c.execute('SELECT role, user_id FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, member_id))
    target_member = c.fetchone()
    
    if not target_member:
        conn.close()
        return jsonify({'success': False, 'message': 'Member not found in group'})
    
    # Cannot kick creator or yourself
    if target_member[0] == 'creator' or target_member[1] == session['user_id']:
        conn.close()
        return jsonify({'success': False, 'message': 'Cannot kick creator or yourself'})
    
    # Only creator can kick admins
    if target_member[0] == 'admin' and group[0] != session['user_id']:
        conn.close()
        return jsonify({'success': False, 'message': 'Only creator can kick admins'})
    
    # Get member username for notification
    c.execute('SELECT username FROM users WHERE id = ?', (member_id,))
    member_name = c.fetchone()[0]
    
    # Remove member from group
    c.execute('DELETE FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, member_id))
    conn.commit()
    conn.close()
    
    # Send notification to kicked member
    try:
        socketio.emit('group_kicked', {
            'group_id': group_id,
            'message': f'You have been removed from the group'
        }, to=str(member_id))
    except Exception as e:
        print(f"Socket emit error: {e}")
    
    return jsonify({'success': True, 'message': f'{member_name} has been removed from the group'})

@app.route('/groups/<int:group_id>/promote-member', methods=['POST'])
def promote_group_member(group_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json()
    member_id = data.get('member_id')
    
    if not member_id:
        return jsonify({'success': False, 'message': 'Member ID is required'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if current user is creator
    c.execute('SELECT creator_id FROM groups WHERE id = ?', (group_id,))
    group = c.fetchone()
    if not group:
        conn.close()
        return jsonify({'success': False, 'message': 'Group not found'})
    
    if group[0] != session['user_id']:
        conn.close()
        return jsonify({'success': False, 'message': 'Only creator can promote members to admin'})
    
    # Check target member exists and is not already admin/creator
    c.execute('SELECT role FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, member_id))
    target_member = c.fetchone()
    
    if not target_member:
        conn.close()
        return jsonify({'success': False, 'message': 'Member not found in group'})
    
    if target_member[0] in ['admin', 'creator']:
        conn.close()
        return jsonify({'success': False, 'message': 'Member is already an admin or creator'})
    
    # Get member username for notification
    c.execute('SELECT username FROM users WHERE id = ?', (member_id,))
    member_name = c.fetchone()[0]
    
    # Promote member to admin
    c.execute('UPDATE group_members SET role = ? WHERE group_id = ? AND user_id = ?', ('admin', group_id, member_id))
    conn.commit()
    conn.close()
    
    # Send notification to promoted member
    try:
        socketio.emit('group_promoted', {
            'group_id': group_id,
            'message': f'You have been promoted to admin'
        }, to=str(member_id))
    except Exception as e:
        print(f"Socket emit error: {e}")
    
    return jsonify({'success': True, 'message': f'{member_name} has been promoted to admin'})

@app.route('/groups/<int:group_id>/demote-member', methods=['POST'])
def demote_group_member(group_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json()
    member_id = data.get('member_id')
    
    if not member_id:
        return jsonify({'success': False, 'message': 'Member ID is required'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if current user is creator
    c.execute('SELECT creator_id FROM groups WHERE id = ?', (group_id,))
    group = c.fetchone()
    if not group:
        conn.close()
        return jsonify({'success': False, 'message': 'Group not found'})
    
    if group[0] != session['user_id']:
        conn.close()
        return jsonify({'success': False, 'message': 'Only creator can demote admins'})
    
    # Check target member exists and is admin
    c.execute('SELECT role FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, member_id))
    target_member = c.fetchone()
    
    if not target_member:
        conn.close()
        return jsonify({'success': False, 'message': 'Member not found in group'})
    
    if target_member[0] != 'admin':
        conn.close()
        return jsonify({'success': False, 'message': 'Member is not an admin'})
    
    # Get member username for notification
    c.execute('SELECT username FROM users WHERE id = ?', (member_id,))
    member_name = c.fetchone()[0]
    
    # Demote admin to member
    c.execute('UPDATE group_members SET role = ? WHERE group_id = ? AND user_id = ?', ('member', group_id, member_id))
    conn.commit()
    conn.close()
    
    # Send notification to demoted member
    try:
        socketio.emit('group_demoted', {
            'group_id': group_id,
            'message': f'You have been demoted to member'
        }, to=str(member_id))
    except Exception as e:
        print(f"Socket emit error: {e}")
    
    return jsonify({'success': True, 'message': f'{member_name} has been demoted to member'})

@app.route('/groups/<int:group_id>/settings', methods=['GET', 'POST'])
def group_settings(group_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if user is creator or admin
    c.execute('SELECT creator_id, name, description, is_private FROM groups WHERE id = ?', (group_id,))
    group = c.fetchone()
    if not group:
        conn.close()
        return jsonify({'success': False, 'message': 'Group not found'})
    
    c.execute('SELECT role FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, session['user_id']))
    member = c.fetchone()
    
    if not member or (member[0] not in ['admin', 'creator'] and group[0] != session['user_id']):
        conn.close()
        return jsonify({'success': False, 'message': 'Only admins can modify group settings'})
    
    if request.method == 'GET':
        conn.close()
        return jsonify({
            'success': True,
            'settings': {
                'name': group[1],
                'description': group[2],
                'is_private': bool(group[3])
            }
        })
    
    # POST - Update settings
    data = request.get_json()
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    is_private = data.get('is_private', False)
    
    if not name:
        conn.close()
        return jsonify({'success': False, 'message': 'Group name is required'})
    
    if len(name) > 50:
        conn.close()
        return jsonify({'success': False, 'message': 'Group name must be 50 characters or less'})
    
    # Update group settings
    c.execute('UPDATE groups SET name = ?, description = ?, is_private = ? WHERE id = ?',
              (name, description, 1 if is_private else 0, group_id))
    conn.commit()
    
    # Get all group members for notification
    c.execute('SELECT user_id FROM group_members WHERE group_id = ?', (group_id,))
    members = c.fetchall()
    conn.close()
    
    # Notify all group members about settings change
    try:
        for member in members:
            socketio.emit('group_settings_updated', {
                'group_id': group_id,
                'name': name,
                'description': description,
                'is_private': is_private,
                'message': 'Group settings have been updated'
            }, to=str(member[0]))
    except Exception as e:
        print(f"Socket emit error: {e}")
    
    return jsonify({'success': True, 'message': 'Group settings updated successfully'})

@app.route('/groups/<int:group_id>/picture', methods=['POST', 'DELETE'])
def group_picture(group_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if user is creator or admin
    c.execute('SELECT creator_id FROM groups WHERE id = ?', (group_id,))
    group = c.fetchone()
    if not group:
        conn.close()
        return jsonify({'success': False, 'message': 'Group not found'})
    
    c.execute('SELECT role FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, session['user_id']))
    member = c.fetchone()
    
    if not member or (member[0] not in ['admin', 'creator'] and group[0] != session['user_id']):
        conn.close()
        return jsonify({'success': False, 'message': 'Only admins can modify group picture'})
    
    if request.method == 'POST':
        data = request.get_json()
        image_data = data.get('image')
        
        if not image_data or not image_data.startswith('data:image/'):
            conn.close()
            return jsonify({'success': False, 'message': 'Invalid image format'})
        
        if len(image_data) > 2 * 1024 * 1024:
            conn.close()
            return jsonify({'success': False, 'message': 'Image too large (max 2MB)'})
        
        c.execute('UPDATE groups SET group_picture = ? WHERE id = ?', (image_data, group_id))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Group picture updated successfully'})
    
    else:  # DELETE
        c.execute('UPDATE groups SET group_picture = NULL WHERE id = ?', (group_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Group picture removed successfully'})

@app.route('/groups/<int:group_id>/delete', methods=['POST'])
def delete_group(group_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if user is creator or admin
    c.execute('SELECT creator_id FROM groups WHERE id = ?', (group_id,))
    group = c.fetchone()
    if not group:
        conn.close()
        return jsonify({'success': False, 'message': 'Group not found'})
    
    c.execute('SELECT role FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, session['user_id']))
    member = c.fetchone()
    
    # Only creator or admin can delete group completely
    if group[0] == session['user_id'] or (member and member[0] == 'admin'):
        # Delete entire group
        c.execute('DELETE FROM group_messages WHERE group_id = ?', (group_id,))
        c.execute('DELETE FROM group_members WHERE group_id = ?', (group_id,))
        c.execute('DELETE FROM groups WHERE id = ?', (group_id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Group deleted successfully'})
    else:
        # Regular user - just leave the group
        if member:
            c.execute('DELETE FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, session['user_id']))
            conn.commit()
            conn.close()
            return jsonify({'success': True, 'message': 'Left group successfully'})
        else:
            conn.close()
            return jsonify({'success': False, 'message': 'Not a member of this group'})

@app.route('/groups/public')
def list_public_groups():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Get public groups that user is not a member of
    c.execute('''
        SELECT g.id, g.name, g.description, g.creator_id, g.created_at,
               u.username as creator_name,
               COUNT(DISTINCT gm.user_id) as member_count
        FROM groups g
        JOIN users u ON g.creator_id = u.id
        LEFT JOIN group_members gm ON g.id = gm.group_id
        WHERE g.is_private = 0 AND g.id NOT IN (
            SELECT group_id FROM group_members WHERE user_id = ?
        )
        GROUP BY g.id, g.name, g.description, g.creator_id, g.created_at, u.username
        ORDER BY member_count DESC, g.created_at DESC
    ''', (session['user_id'],))
    
    groups = c.fetchall()
    conn.close()
    
    return jsonify({
        'success': True,
        'groups': [{
            'id': g[0],
            'name': g[1],
            'description': g[2],
            'creator_id': g[3],
            'created_at': g[4],
            'creator_name': g[5],
            'member_count': g[6]
        } for g in groups]
    })

@app.route('/admin/delete-group', methods=['POST'])
def admin_delete_group():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    try:
        data = request.get_json()
        group_id = data.get('id')
        
        if not group_id:
            return jsonify({'success': False, 'message': 'Group ID is required'})
        
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        
        # Check if group exists
        c.execute('SELECT name FROM groups WHERE id=?', (group_id,))
        group = c.fetchone()
        
        if not group:
            conn.close()
            return jsonify({'success': False, 'message': 'Group not found'})
        
        # Admin can delete any group completely
        c.execute('DELETE FROM group_messages WHERE group_id = ?', (group_id,))
        c.execute('DELETE FROM group_members WHERE group_id = ?', (group_id,))
        c.execute('DELETE FROM groups WHERE id = ?', (group_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': f'Group "{group[0]}" deleted successfully'})
            
    except Exception as e:
        print(f"Error deleting group: {e}")
        return jsonify({'success': False, 'message': 'Error deleting group'})

@app.route('/groups/<int:group_id>/members')
def get_group_members(group_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if user is a member
    c.execute('SELECT id FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, session['user_id']))
    if not c.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'Not a member of this group'}), 403
    
    # Get members
    c.execute('''
        SELECT u.id, u.username, u.profile_picture, gm.role, gm.joined_at
        FROM group_members gm
        JOIN users u ON gm.user_id = u.id
        WHERE gm.group_id = ?
        ORDER BY 
            CASE gm.role 
                WHEN 'creator' THEN 1 
                WHEN 'admin' THEN 2 
                ELSE 3 
            END,
            gm.joined_at ASC
    ''', (group_id,))
    
    members = c.fetchall()
    conn.close()
    
    return jsonify({
        'success': True,
        'members': [{
            'id': m[0],
            'username': m[1],
            'profile_picture': m[2],
            'role': m[3],
            'joined_at': m[4]
        } for m in members]
    })

@app.route('/groups/messages/delete-for-everyone', methods=['POST'])
def delete_group_message_for_everyone():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json() if request.is_json else request.form
    message_id = data.get('message_id')
    
    if not message_id:
        return jsonify({'success': False, 'message': 'message_id is required'}), 400
    
    try:
        message_id = int(message_id)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid message_id'}), 400
    
    my_id = session['user_id']
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if message exists and user is the sender
    c.execute('SELECT sender_id, group_id, content FROM group_messages WHERE id=?', (message_id,))
    message = c.fetchone()
    
    if not message:
        conn.close()
        return jsonify({'success': False, 'message': 'Message not found'}), 404
    
    sender_id, group_id, content = message
    
    # Only allow sender to delete for everyone
    if sender_id != my_id:
        conn.close()
        return jsonify({'success': False, 'message': 'You can only delete your own messages for everyone'}), 403
    
    # Get all group members for notification
    c.execute('SELECT user_id FROM group_members WHERE group_id = ?', (group_id,))
    members = c.fetchall()
    
    # Delete message from database completely
    c.execute('DELETE FROM group_messages WHERE id=?', (message_id,))
    
    conn.commit()
    conn.close()
    
    # Notify all group members that message was deleted
    try:
        for member in members:
            socketio.emit('group_message_deleted_for_everyone', {
                'message_id': message_id,
                'group_id': group_id,
                'deleted_by': my_id
            }, to=str(member[0]))
    except Exception as e:
        print(f"Socket emit error: {e}")
    
    return jsonify({'success': True, 'message': 'Group message deleted for everyone'})

# Favorites functionality
@app.route('/favorites/add', methods=['POST'])
def add_favorite():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json()
    item_type = data.get('item_type')  # 'user', 'group', 'message'
    item_id = data.get('item_id')
    
    if not item_type or not item_id:
        return jsonify({'success': False, 'message': 'Item type and ID are required'})
    
    if item_type not in ['user', 'group', 'message']:
        return jsonify({'success': False, 'message': 'Invalid item type'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    try:
        c.execute('INSERT OR IGNORE INTO favorites (user_id, item_type, item_id) VALUES (?, ?, ?)',
                  (session['user_id'], item_type, item_id))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Added to favorites'})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': 'Failed to add to favorites'})

@app.route('/favorites/list')
def list_favorites():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Get favorite users
    c.execute('''
        SELECT f.item_id, u.username, u.profile_picture, f.created_at
        FROM favorites f
        JOIN users u ON f.item_id = u.id
        WHERE f.user_id = ? AND f.item_type = 'user'
        ORDER BY f.created_at DESC
    ''', (session['user_id'],))
    favorite_users = c.fetchall()
    
    # Get favorite groups
    c.execute('''
        SELECT f.item_id, g.name, g.description, f.created_at
        FROM favorites f
        JOIN groups g ON f.item_id = g.id
        WHERE f.user_id = ? AND f.item_type = 'group'
        ORDER BY f.created_at DESC
    ''', (session['user_id'],))
    favorite_groups = c.fetchall()
    
    conn.close()
    
    return jsonify({
        'success': True,
        'favorites': {
            'users': [{
                'id': u[0],
                'username': u[1],
                'profile_picture': u[2],
                'added_at': u[3]
            } for u in favorite_users],
            'groups': [{
                'id': g[0],
                'name': g[1],
                'description': g[2],
                'added_at': g[3]
            } for g in favorite_groups]
        }
    })

# File upload functionality
@app.route('/upload-file', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'})
    
    # Check file size (5MB limit for base64 storage)
    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)
    
    if file_size > 5 * 1024 * 1024:  # 5MB
        return jsonify({'success': False, 'message': 'File size exceeds 5MB limit'})
    
    # Allowed file types
    allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx', '.txt', '.zip', '.mp4', '.mp3'}
    file_extension = os.path.splitext(file.filename)[1].lower()
    
    if file_extension not in allowed_extensions:
        return jsonify({'success': False, 'message': 'File type not allowed'})
    
    try:
        # Read file content and encode as base64
        file_content = file.read()
        file_base64 = base64.b64encode(file_content).decode('utf-8')
        
        # Generate unique filename
        import uuid
        unique_filename = str(uuid.uuid4()) + file_extension
        
        # Save file info to database with base64 content
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        c.execute('''
            INSERT INTO file_uploads (filename, original_name, file_size, file_type, uploader_id, file_data)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (unique_filename, file.filename, file_size, file.content_type or 'application/octet-stream', 
              session['user_id'], file_base64))
        file_id = c.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'File uploaded successfully',
            'file': {
                'id': file_id,
                'filename': unique_filename,
                'original_name': file.filename,
                'size': file_size,
                'url': f'/files/{unique_filename}'
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to upload file'})

@app.route('/files/<filename>')
def serve_file(filename):
    if 'user_id' not in session:
        return 'Unauthorized', 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Get file data from database
    c.execute('SELECT uploader_id, file_data, file_type, original_name FROM file_uploads WHERE filename = ?', (filename,))
    result = c.fetchone()
    
    if not result:
        conn.close()
        return 'File not found', 404
    
    uploader_id, file_data, file_type, original_name = result
    user_id = session['user_id']
    
    # Check access permissions
    has_access = False
    
    # Allow access if user is uploader
    if uploader_id == user_id:
        has_access = True
    else:
        # Check if file was shared with user in messages
        c.execute('''
            SELECT 1 FROM messages 
            WHERE (sender_id = ? OR receiver_id = ?) 
            AND file_url LIKE ?
        ''', (user_id, user_id, f'%{filename}%'))
        
        if c.fetchone():
            has_access = True
        else:
            # Check if file was shared in group messages user is member of
            c.execute('''
                SELECT 1 FROM group_messages gm
                JOIN group_members gme ON gm.group_id = gme.group_id
                WHERE gme.user_id = ? AND gm.file_url LIKE ?
            ''', (user_id, f'%{filename}%'))
            
            if c.fetchone():
                has_access = True
    
    conn.close()
    
    if not has_access:
        return 'Access denied', 403
    
    # Decode base64 and serve file
    try:
        file_content = base64.b64decode(file_data)
        from flask import Response
        return Response(
            file_content,
            mimetype=file_type,
            headers={
                'Content-Disposition': f'attachment; filename="{original_name}"',
                'Content-Length': str(len(file_content)),
                'Cache-Control': 'no-cache'
            }
        )
    except Exception as e:
        return 'Error serving file', 500

@app.route('/files/my-uploads')
def my_uploads():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('''
        SELECT id, filename, original_name, file_size, file_type, created_at
        FROM file_uploads 
        WHERE uploader_id = ?
        ORDER BY created_at DESC
    ''', (session['user_id'],))
    
    files = c.fetchall()
    conn.close()
    
    return jsonify({
        'success': True,
        'files': [{
            'id': f[0],
            'filename': f[1],
            'original_name': f[2],
            'size': f[3],
            'type': f[4],
            'uploaded_at': f[5],
            'url': f'/files/{f[1]}'
        } for f in files]
    })

@app.route('/files/delete/<int:file_id>', methods=['DELETE'])
def delete_file(file_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if user owns the file
    c.execute('SELECT filename FROM file_uploads WHERE id = ? AND uploader_id = ?', 
              (file_id, session['user_id']))
    result = c.fetchone()
    
    if not result:
        conn.close()
        return jsonify({'success': False, 'message': 'File not found or access denied'}), 404
    
    # Delete from database (file data is stored in database)
    c.execute('DELETE FROM file_uploads WHERE id = ?', (file_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'File deleted successfully'})



@app.route('/admin/user-profile-pic/<int:user_id>')
def admin_get_user_profile_pic(user_id):
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('SELECT profile_picture FROM users WHERE id=?', (user_id,))
    user = c.fetchone()
    conn.close()
    
    if user and user[0]:
        return jsonify({'success': True, 'profile_picture': user[0]})
    else:
        return jsonify({'success': True, 'profile_picture': None})

@app.route('/admin/update-profile-pic/<int:user_id>', methods=['POST'])
def admin_update_profile_pic(user_id):
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    data = request.get_json()
    image_data = data.get('image')
    
    if not image_data or not image_data.startswith('data:image/'):
        return jsonify({'success': False, 'message': 'Invalid image format'})
    
    if len(image_data) > 2 * 1024 * 1024:
        return jsonify({'success': False, 'message': 'Image too large (max 2MB)'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('UPDATE users SET profile_picture=? WHERE id=?', (image_data, user_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Profile picture updated'})

@app.route('/admin/remove-profile-pic/<int:user_id>', methods=['POST'])
def admin_remove_profile_pic(user_id):
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('UPDATE users SET profile_picture=NULL WHERE id=?', (user_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Profile picture removed'})

@app.route('/users/mute', methods=['POST'])
def mute_user():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json() if request.is_json else request.form
    user_id = data.get('user_id')
    
    if not user_id:
        return jsonify({'success': False, 'message': 'user_id is required'}), 400
    
    try:
        user_id = int(user_id)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid user_id'}), 400
    
    my_id = session['user_id']
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Create muted_users table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS muted_users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  muter_id INTEGER NOT NULL,
                  muted_id INTEGER NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (muter_id) REFERENCES users (id),
                  FOREIGN KEY (muted_id) REFERENCES users (id),
                  UNIQUE(muter_id, muted_id))''')
    
    # Mute user
    c.execute('INSERT OR IGNORE INTO muted_users (muter_id, muted_id) VALUES (?, ?)', (my_id, user_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'User muted successfully'})

@app.route('/users/unmute', methods=['POST'])
def unmute_user():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json() if request.is_json else request.form
    user_id = data.get('user_id')
    
    if not user_id:
        return jsonify({'success': False, 'message': 'user_id is required'}), 400
    
    try:
        user_id = int(user_id)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid user_id'}), 400
    
    my_id = session['user_id']
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Unmute user
    c.execute('DELETE FROM muted_users WHERE muter_id=? AND muted_id=?', (my_id, user_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'User unmuted successfully'})

@app.route('/users/muted-status')
def check_muted_status():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'user_id is required'}), 400
    
    try:
        user_id = int(user_id)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid user_id'}), 400
    
    my_id = session['user_id']
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if user is muted
    c.execute('SELECT 1 FROM muted_users WHERE muter_id=? AND muted_id=?', (my_id, user_id))
    is_muted = c.fetchone() is not None
    
    conn.close()
    
    return jsonify({'success': True, 'is_muted': is_muted})

@app.route('/respond-friend-request', methods=['POST'])
def respond_friend_request():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'})
    
    data = request.get_json()
    request_id = data.get('request_id')
    action = data.get('action')
    
    if not request_id or action not in ['accept', 'reject']:
        return jsonify({'success': False, 'message': 'Invalid request'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    c.execute('SELECT sender_id FROM friend_requests WHERE id=? AND receiver_id=?', (request_id, session['user_id']))
    request_data = c.fetchone()
    
    if not request_data:
        conn.close()
        return jsonify({'success': False, 'message': 'Friend request not found'})
    
    status = 'accepted' if action == 'accept' else 'rejected'
    c.execute('UPDATE friend_requests SET status=? WHERE id=?', (status, request_id))
    conn.commit()
    try:
        socketio.emit('friend_request_update', {'request_id': request_id, 'status': status}, to=str(session['user_id']))
    except Exception as e:
        print(f"socket emit error: {e}")
    conn.close()
    
    return jsonify({'success': True, 'message': f'Friend request {status}'})

@app.route('/admin/delete-message', methods=['POST'])
def delete_message():
    if 'admin' not in session:
        return jsonify({'success': False})
    
    data = request.get_json()
    message_id = data.get('id')
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('DELETE FROM contact_messages WHERE id=?', (message_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/admin/delete-user', methods=['POST'])
def delete_user():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    try:
        data = request.get_json()
        user_id = data.get('id')
        reason = data.get('reason', 'Account deleted by admin')
        
        if not user_id:
            return jsonify({'success': False, 'message': 'User ID is required'})
        
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        
        # Get user email first
        c.execute('SELECT email FROM users WHERE id=?', (user_id,))
        user = c.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'success': False, 'message': 'User not found'})
        
        user_email = user[0]
        
        # Use your existing function
        success, message = detect_and_send_deletion_email(user_email, reason)
        
        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message})
            
    except Exception as e:
        print(f"Error deleting user: {e}")
        return jsonify({'success': False, 'message': 'Error deleting user'})

@app.route('/admin/analytics-summary', methods=['GET'])
def admin_analytics_summary():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    # Totals
    c.execute('SELECT COUNT(*) FROM users')
    total_users = c.fetchone()[0]
    c.execute("SELECT status, COUNT(*) FROM users GROUP BY status")
    users_by_status_rows = c.fetchall()
    users_by_status = {row[0] or 'Unknown': row[1] for row in users_by_status_rows}
    c.execute('SELECT COUNT(*) FROM contact_messages')
    total_messages = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM friend_requests')
    total_friend_requests = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM login_logs WHERE login_date = DATE("now")')
    today_logins = c.fetchone()[0]
    conn.close()
    return jsonify({'success': True, 'data': {
        'total_users': total_users,
        'users_by_status': users_by_status,
        'total_messages': total_messages,
        'total_friend_requests': total_friend_requests,
        'today_logins': today_logins
    }})

@app.route('/admin/analytics/timeseries', methods=['GET'])
def admin_analytics_timeseries():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    # days param (default 14)
    try:
        days = min(90, max(1, int(request.args.get('days', 14))))
    except ValueError:
        days = 14
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    # Build date range
    c.execute("SELECT DATE('now', ?) ", (f'-{days-1} day',))
    start_date = c.fetchone()[0]

    # Users per day (by created_at)
    c.execute("""
        SELECT DATE(created_at) as d, COUNT(*)
        FROM users
        WHERE DATE(created_at) >= DATE(?)
        GROUP BY DATE(created_at)
        ORDER BY d
    """, (start_date,))
    users_rows = {row[0]: row[1] for row in c.fetchall()}

    # Messages per day
    c.execute("""
        SELECT DATE(created_at) as d, COUNT(*)
        FROM contact_messages
        WHERE DATE(created_at) >= DATE(?)
        GROUP BY DATE(created_at)
        ORDER BY d
    """, (start_date,))
    messages_rows = {row[0]: row[1] for row in c.fetchall()}

    # Friend requests per day
    c.execute("""
        SELECT DATE(created_at) as d, COUNT(*)
        FROM friend_requests
        WHERE DATE(created_at) >= DATE(?)
        GROUP BY DATE(created_at)
        ORDER BY d
    """, (start_date,))
    friends_rows = {row[0]: row[1] for row in c.fetchall()}

    # Logins per day
    c.execute("""
        SELECT login_date as d, COUNT(*)
        FROM login_logs
        WHERE DATE(login_date) >= DATE(?)
        GROUP BY login_date
        ORDER BY d
    """, (start_date,))
    logins_rows = {row[0]: row[1] for row in c.fetchall()}
    conn.close()

    # Compose full continuous series
    from datetime import datetime as dt, timedelta as td
    start = dt.fromisoformat(start_date)
    labels = []
    users_series = []
    messages_series = []
    friends_series = []
    logins_series = []
    for i in range(days):
        d = (start + td(days=i)).date().isoformat()
        labels.append(d)
        users_series.append(users_rows.get(d, 0))
        messages_series.append(messages_rows.get(d, 0))
        friends_series.append(friends_rows.get(d, 0))
        logins_series.append(logins_rows.get(d, 0))

    return jsonify({'success': True, 'labels': labels, 'users': users_series, 'messages': messages_series, 'friends': friends_series, 'logins': logins_series})

@app.route('/admin/system-settings', methods=['GET'])
def admin_system_settings():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    db_settings = read_settings()
    settings = {
        'site_name': db_settings.get('site_name', 'ChatMind'),
        'smtp_server': db_settings.get('smtp_server', EMAIL_CONFIG.get('smtp_server')),
        'smtp_port': int(db_settings.get('smtp_port', EMAIL_CONFIG.get('smtp_port'))),
        'sender_email': db_settings.get('sender_email', EMAIL_CONFIG.get('sender_email') or ''),
        'google_client_id': db_settings.get('google_client_id', GOOGLE_CLIENT_ID or ''),
        'google_redirect_uri': db_settings.get('google_redirect_uri', GOOGLE_REDIRECT_URI or ''),
        'registration_required_otp': db_settings.get('registration_required_otp', 'true') == 'true'
    }
    return jsonify({'success': True, 'settings': settings})

@app.route('/admin/system-settings', methods=['POST'])
def admin_system_settings_update():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    data = request.get_json() if request.is_json else request.form
    allowed_keys = {'site_name','smtp_server','smtp_port','sender_email','sender_password','google_client_id','google_redirect_uri','registration_required_otp'}
    updates = {}
    for key in allowed_keys:
        if key in data:
            updates[key] = str(data.get(key))
    # simple validations
    if 'smtp_port' in updates:
        try:
            int(updates['smtp_port'])
        except ValueError:
            return jsonify({'success': False, 'message': 'SMTP port must be a number'})
    if 'sender_email' in updates and updates['sender_email']:
        if '@' not in updates['sender_email']:
            return jsonify({'success': False, 'message': 'Invalid sender email'})
    save_settings(updates)
    return jsonify({'success': True, 'message': 'Settings updated successfully'})

@app.route('/admin/email-templates', methods=['GET', 'POST'])
def admin_email_templates():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    if request.method == 'GET':
        s = read_settings()
        templates = {
            'deletion': s.get('template_deletion', 'Dear User, your account has been deleted. Reason: {{reason}}'),
            'update_notification': s.get('template_update_notification', 'Dear {{username}}, your account has been updated. Changes: {{changes}}'),
            'otp': s.get('template_otp', 'Your verification code is: {{otp}}')
        }
        return jsonify({'success': True, 'templates': templates})
    else:
        data = request.get_json() if request.is_json else request.form
        updates = {}
        if 'deletion' in data:
            updates['template_deletion'] = data.get('deletion')
        if 'update_notification' in data:
            updates['template_update_notification'] = data.get('update_notification')
        if 'otp' in data:
            updates['template_otp'] = data.get('otp')
        save_settings(updates)
        return jsonify({'success': True, 'message': 'Templates saved'})

@app.route('/admin/backup/download', methods=['GET'])
def admin_backup_download():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    try:
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        c.execute('SELECT id, username, email, status FROM users')
        users = c.fetchall()
        c.execute('SELECT id, name, email, subject, message, created_at FROM contact_messages ORDER BY created_at DESC')
        messages = c.fetchall()
        c.execute('SELECT id, sender_id, receiver_id, status, created_at FROM friend_requests ORDER BY created_at DESC')
        friend_requests = c.fetchall()
        c.execute('SELECT id, user_id, login_date FROM login_logs ORDER BY login_date DESC')
        login_logs = c.fetchall()
        conn.close()
        payload = {
            'users': users,
            'contact_messages': messages,
            'friend_requests': friend_requests,
            'login_logs': login_logs
        }
        from flask import Response
        import json
        return Response(
            json.dumps(payload, ensure_ascii=False),
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename="backup.json"'}
        )
    except Exception as e:
        print(f"Backup download error: {e}")
        return jsonify({'success': False, 'message': 'Failed to download backup'})

@app.route('/admin/notifications/send-test', methods=['POST'])
def admin_notifications_send_test():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    data = request.get_json() if request.is_json else request.form
    to_email = data.get('to')
    if not to_email:
        return jsonify({'success': False, 'message': 'Recipient email required'})
    # Merge settings with defaults
    s = read_settings()
    smtp_server = s.get('smtp_server', EMAIL_CONFIG['smtp_server'])
    smtp_port = int(s.get('smtp_port', EMAIL_CONFIG['smtp_port']))
    sender_email = s.get('sender_email', EMAIL_CONFIG['sender_email'])
    sender_password = s.get('sender_password', EMAIL_CONFIG['sender_password'])
    if not sender_email or not sender_password:
        return jsonify({'success': False, 'message': 'Email not configured'}), 400
    try:
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
        server.starttls()
        server.login(sender_email, sender_password)
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = to_email
        msg['Subject'] = 'Test Notification'
        msg.attach(MIMEText('This is a test notification from Admin.', 'plain'))
        server.send_message(msg)
        server.quit()
        return jsonify({'success': True, 'message': 'Test email sent'})
    except Exception as e:
        print(f"Test email error: {e}")
        return jsonify({'success': False, 'message': 'Failed to send test email'})

@app.route('/admin/backup/export', methods=['GET'])
def admin_backup_export():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    try:
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        c.execute('SELECT id, username, email, status FROM users')
        users = c.fetchall()
        c.execute('SELECT id, name, email, subject, message, created_at FROM contact_messages ORDER BY created_at DESC')
        messages = c.fetchall()
        c.execute('SELECT id, sender_id, receiver_id, status, created_at FROM friend_requests ORDER BY created_at DESC')
        friend_requests = c.fetchall()
        c.execute('SELECT id, user_id, login_date FROM login_logs ORDER BY login_date DESC')
        login_logs = c.fetchall()
        conn.close()
        return jsonify({'success': True, 'export': {
            'users': users,
            'contact_messages': messages,
            'friend_requests': friend_requests,
            'login_logs': login_logs
        }})
    except Exception as e:
        print(f"Backup export error: {e}")
        return jsonify({'success': False, 'message': 'Failed to export backup'})

@app.route('/admin/security-report', methods=['GET'])
def admin_security_report():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM users WHERE password IS NULL OR password = ""')
    password_null = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM users WHERE verified = 0')
    unverified = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM users WHERE status = 'Inactive'")
    inactive = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM users WHERE status = 'Suspended'")
    suspended = c.fetchone()[0]
    conn.close()
    return jsonify({'success': True, 'report': {
        'password_missing_or_empty': password_null,
        'unverified_accounts': unverified,
        'inactive_accounts': inactive,
        'suspended_accounts': suspended
    }})

@app.route('/admin/notifications/test', methods=['POST'])
def admin_notifications_test():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    # This is a dry-run notifier: returns whether email is configured
    configured = bool(EMAIL_CONFIG.get('sender_email') and EMAIL_CONFIG.get('sender_password'))
    return jsonify({'success': True, 'notifier_ready': configured})

def _load_email_runtime_config():
    s = read_settings()
    return {
        'smtp_server': s.get('smtp_server', EMAIL_CONFIG['smtp_server']),
        'smtp_port': int(s.get('smtp_port', EMAIL_CONFIG['smtp_port'])),
        'sender_email': s.get('sender_email', EMAIL_CONFIG['sender_email']),
        'sender_password': s.get('sender_password', EMAIL_CONFIG['sender_password'])
    }

@app.route('/admin/notifications/send', methods=['POST'])
def admin_notifications_send():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    data = request.get_json() if request.is_json else request.form
    user_id = data.get('user_id')
    to_email = data.get('email')
    subject = data.get('subject')
    body = data.get('message')
    if not subject or not body:
        return jsonify({'success': False, 'message': 'Subject and message are required'})
    if not to_email and not user_id:
        return jsonify({'success': False, 'message': 'User or email is required'})

    # Resolve email by user_id if needed
    resolved_email = to_email
    resolved_user_id = None
    if user_id:
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        c.execute('SELECT id, email FROM users WHERE id=?', (user_id,))
        user = c.fetchone()
        conn.close()
        if not user:
            return jsonify({'success': False, 'message': 'User not found'})
        resolved_user_id = user[0]
        resolved_email = resolved_email or user[1]
    if not resolved_email:
        return jsonify({'success': False, 'message': 'Recipient email not available'})

    cfg = _load_email_runtime_config()
    if not cfg['sender_email'] or not cfg['sender_password']:
        return jsonify({'success': False, 'message': 'Email not configured'}), 400

    # Send email and log it
    try:
        server = smtplib.SMTP(cfg['smtp_server'], cfg['smtp_port'], timeout=10)
        server.starttls()
        server.login(cfg['sender_email'], cfg['sender_password'])
        msg = MIMEMultipart()
        msg['From'] = cfg['sender_email']
        msg['To'] = resolved_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        server.send_message(msg)
        server.quit()
        status = 'sent'
    except Exception as e:
        print(f"Admin send notification error: {e}")
        status = 'failed'

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('INSERT INTO admin_notifications (user_id, email, subject, message, status) VALUES (?, ?, ?, ?, ?)',
              (resolved_user_id, resolved_email, subject, body, status))
    conn.commit()
    conn.close()

    return jsonify({'success': status == 'sent', 'message': f'Notification {status}'})

@app.route('/admin/notifications/list', methods=['GET'])
def admin_notifications_list():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('SELECT id, user_id, email, subject, status, created_at FROM admin_notifications ORDER BY created_at DESC LIMIT 100')
    rows = c.fetchall()
    conn.close()
    return jsonify({'success': True, 'notifications': rows})

@app.route('/admin/logs/recent', methods=['GET'])
def admin_logs_recent():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('SELECT id, user_id, login_date FROM login_logs ORDER BY login_date DESC LIMIT 50')
    login_logs = c.fetchall()
    c.execute('SELECT id, sender_id, receiver_id, status, created_at FROM friend_requests ORDER BY created_at DESC LIMIT 50')
    friend_requests = c.fetchall()
    c.execute('SELECT id, name, email, subject, created_at FROM contact_messages ORDER BY created_at DESC LIMIT 50')
    messages = c.fetchall()
    conn.close()
    return jsonify({'success': True, 'logs': {
        'login_logs': login_logs,
        'friend_requests': friend_requests,
        'contact_messages': messages
    }})

@app.route('/admin/logs/list', methods=['GET'])
def admin_logs_list():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    log_type = request.args.get('type', 'login')
    try:
        offset = int(request.args.get('offset', 0))
        limit = min(100, int(request.args.get('limit', 25)))
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid offset/limit'}), 400

    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    total = 0
    rows = []
    if log_type == 'login':
        c.execute('SELECT COUNT(*) FROM login_logs')
        total = c.fetchone()[0]
        c.execute('SELECT id, user_id, login_date FROM login_logs ORDER BY login_date DESC LIMIT ? OFFSET ?', (limit, offset))
        rows = c.fetchall()
    elif log_type == 'friend':
        c.execute('SELECT COUNT(*) FROM friend_requests')
        total = c.fetchone()[0]
        c.execute('SELECT id, sender_id, receiver_id, status, created_at FROM friend_requests ORDER BY created_at DESC LIMIT ? OFFSET ?', (limit, offset))
        rows = c.fetchall()
    elif log_type == 'message':
        c.execute('SELECT COUNT(*) FROM contact_messages')
        total = c.fetchone()[0]
        c.execute('SELECT id, name, email, subject, created_at FROM contact_messages ORDER BY created_at DESC LIMIT ? OFFSET ?', (limit, offset))
        rows = c.fetchall()
    else:
        conn.close()
        return jsonify({'success': False, 'message': 'Invalid log type'}), 400
    conn.close()
    return jsonify({'success': True, 'type': log_type, 'total': total, 'rows': rows, 'offset': offset, 'limit': limit})

@app.route('/admin/system-health', methods=['GET'])
def admin_system_health():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    import psutil
    import os
    
    try:
        # Get real system metrics
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Database connection test
        db_connected = True
        try:
            conn = sqlite3.connect(get_db_path())
            conn.execute('SELECT 1')
            conn.close()
        except Exception:
            db_connected = False
        
        health_data = {
            'server_status': 'online',
            'database_connected': db_connected,
            'memory_usage': round(memory.percent, 1),
            'storage_usage': round((disk.used / disk.total) * 100, 1),
            'cpu_usage': round(cpu_percent, 1),
            'online_users': len(ONLINE_USERS),
            'uptime': 'Available'
        }
        
        return jsonify({'success': True, 'health': health_data})
    except ImportError:
        # Fallback to simulated data if psutil not available
        import random
        health_data = {
            'server_status': 'online',
            'database_connected': True,
            'memory_usage': round(random.uniform(60, 90), 1),
            'storage_usage': round(random.uniform(40, 70), 1),
            'cpu_usage': round(random.uniform(20, 60), 1),
            'online_users': len(ONLINE_USERS),
            'uptime': 'Simulated'
        }
        return jsonify({'success': True, 'health': health_data})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/email-templates/defaults', methods=['GET'])
def admin_email_templates_defaults():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    templates = {
        'deletion': 'Dear User, your account has been deleted. Reason: {{reason}}',
        'update_notification': 'Dear {{username}}, your account has been updated. Changes: {{changes}}',
        'otp': 'Your verification code is: {{otp}}'
    }
    return jsonify({'success': True, 'templates': templates})

@app.route('/admin/active-users', methods=['GET'])
def admin_active_users():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Get users with their message counts and login activity
    c.execute('''
        SELECT u.id, u.username, u.email, u.status,
               COUNT(DISTINCT m.id) as message_count,
               COUNT(DISTINCT ll.id) as login_count,
               MAX(ll.login_date) as last_login
        FROM users u
        LEFT JOIN messages m ON (u.id = m.sender_id OR u.id = m.receiver_id)
        LEFT JOIN login_logs ll ON u.id = ll.user_id
        WHERE u.status = 'Active'
        GROUP BY u.id, u.username, u.email, u.status
        ORDER BY message_count DESC, login_count DESC
        LIMIT 20
    ''')
    
    users = []
    for row in c.fetchall():
        user_id, username, email, status, msg_count, login_count, last_login = row
        is_online = user_id in ONLINE_USERS
        users.append({
            'id': user_id,
            'username': username,
            'email': email,
            'status': status,
            'message_count': msg_count or 0,
            'login_count': login_count or 0,
            'last_login': last_login,
            'is_online': is_online
        })
    
    conn.close()
    return jsonify({'success': True, 'users': users})
@app.route('/admin/add-user', methods=['POST'])
def add_user():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'})

    try:
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        status = request.form.get('status', 'Active')

        if not username or not email or not password:
            return jsonify({'success': False, 'message': 'Username, email and password are required'})

        # Basic email format check
        if '@' not in email or '.' not in email.split('@')[-1]:
            return jsonify({'success': False, 'message': 'Invalid email address'})

        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()

        # Ensure unique username/email
        c.execute('SELECT 1 FROM users WHERE username=?', (username,))
        if c.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Username already exists'})
        c.execute('SELECT 1 FROM users WHERE email=?', (email,))
        if c.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Email already exists'})

        hashed_password = hash_password(password)
        c.execute(
            'INSERT INTO users (username, email, password, verified, status, created_at) VALUES (?, ?, ?, 1, ?, CURRENT_TIMESTAMP)',
            (username, email, hashed_password, status)
        )
        conn.commit()
        user_id = c.lastrowid
        conn.close()

        return jsonify({
            'success': True,
            'message': 'User created successfully',
            'user': {
                'id': user_id,
                'username': username,
                'email': email,
                'status': status
            }
        })
    except Exception as e:
        print(f"Error adding user: {e}")
        return jsonify({'success': False, 'message': 'Error creating user'})

@app.route('/change-password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'})
    
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({'success': False, 'message': 'Current and new password are required'})
    
    # Validate new password
    is_valid, message = validate_password(new_password)
    if not is_valid:
        return jsonify({'success': False, 'message': message})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Get current password hash
    c.execute('SELECT password FROM users WHERE id=?', (session['user_id'],))
    user = c.fetchone()
    
    if not user or not verify_password(current_password, user[0]):
        conn.close()
        return jsonify({'success': False, 'message': 'Current password is incorrect'})
    
    # Update password
    new_hash = hash_password(new_password)
    c.execute('UPDATE users SET password=? WHERE id=?', (new_hash, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Password changed successfully'})

@app.route('/upload-profile-picture', methods=['POST'])
def upload_profile_picture():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'})
    
    # Handle both JSON and form data
    if request.is_json:
        data = request.get_json()
        image_data = data.get('image')
    else:
        # Handle file upload
        if 'profile_picture' not in request.files:
            return jsonify({'success': False, 'message': 'No file provided'})
        
        file = request.files['profile_picture']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'})
        
        # Check file size (5MB limit)
        file.seek(0, 2)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > 5 * 1024 * 1024:
            return jsonify({'success': False, 'message': 'File size exceeds 5MB limit'})
        
        # Check file type
        allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}
        file_extension = os.path.splitext(file.filename)[1].lower()
        
        if file_extension not in allowed_extensions:
            return jsonify({'success': False, 'message': 'Invalid file type. Only JPG, PNG, GIF, and WebP are allowed'})
        
        # Convert to base64
        import base64
        file_content = file.read()
        mime_type = f"image/{file_extension[1:]}"
        if file_extension == '.jpg':
            mime_type = 'image/jpeg'
        image_data = f"data:{mime_type};base64,{base64.b64encode(file_content).decode('utf-8')}"
    
    try:
        # Validate base64 image data format
        if not image_data or not image_data.startswith('data:image/'):
            return jsonify({'success': False, 'message': 'Invalid image format'})
        
        # Check image size (limit to 2MB for base64)
        if len(image_data) > 2 * 1024 * 1024:
            return jsonify({'success': False, 'message': 'Image too large (max 2MB)'})
        
        # Check if user already has a profile picture
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        c.execute('SELECT profile_picture FROM users WHERE id=?', (session['user_id'],))
        existing_pic = c.fetchone()
        
        # Update or insert profile picture
        c.execute('UPDATE users SET profile_picture=? WHERE id=?', (image_data, session['user_id']))
        conn.commit()
        conn.close()
        
        action = 'updated' if existing_pic and existing_pic[0] else 'uploaded'
        return jsonify({'success': True, 'message': f'Profile picture {action} successfully'})
    
    except sqlite3.Error as e:
        print(f"Database error during profile picture upload: {e}")
        return jsonify({'success': False, 'message': 'Database error occurred'})
    except Exception as e:
        print(f"Profile picture upload error: {e}")
        return jsonify({'success': False, 'message': 'Failed to upload profile picture'})

@app.route('/remove-profile-picture', methods=['POST'])
def remove_profile_picture():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'})
    
    try:
        with sqlite3.connect(get_db_path()) as conn:
            c = conn.cursor()
            c.execute('UPDATE users SET profile_picture=NULL WHERE id=?', (session['user_id'],))
            conn.commit()
        
        return jsonify({'success': True, 'message': 'Profile picture removed successfully'})
    
    except Exception as e:
        print(f"Profile picture removal error: {e}")
        return jsonify({'success': False, 'message': 'Failed to remove profile picture'})

@app.route('/admin/check-email', methods=['POST'])
def check_email():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    data = request.get_json()
    user_email = data.get('email')
    
    if not user_email:
        return jsonify({'success': False, 'message': 'Email is required'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('SELECT id, username, email FROM users WHERE email=?', (user_email,))
    user = c.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'success': True, 
            'exists': True, 
            'user': {
                'id': user[0],
                'username': user[1],
                'email': user[2]
            }
        })
    else:
        return jsonify({'success': True, 'exists': False})

@app.route('/admin/user-blocks/<int:user_id>')
def admin_user_blocks(user_id):
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    # Users who block this user (blocked_by)
    c.execute('''
        SELECT u.id, u.username, 'blocked_by' as type
        FROM blocked_users b
        JOIN users u ON b.blocker_id = u.id
        WHERE b.blocked_id = ?
    ''', (user_id,))
    blocked_by = c.fetchall()
    
    # Users this user blocks (blocks)
    c.execute('''
        SELECT u.id, u.username, 'blocks' as type
        FROM blocked_users b
        JOIN users u ON b.blocked_id = u.id
        WHERE b.blocker_id = ?
    ''', (user_id,))
    blocks = c.fetchall()
    
    all_blocks = blocked_by + blocks
    conn.close()
    
    return jsonify({'success': True, 'blocks': all_blocks})

@app.route('/admin/manage-block', methods=['POST'])
def admin_manage_block():
    if 'admin' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    data = request.get_json()
    user1_id = data.get('user1_id')
    user2_id = data.get('user2_id')
    action = data.get('action')  # 'block' or 'unblock'
    
    if not user1_id or not user2_id or action not in ['block', 'unblock']:
        return jsonify({'success': False, 'message': 'Invalid parameters'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    if action == 'block':
        c.execute('INSERT OR IGNORE INTO blocked_users (blocker_id, blocked_id) VALUES (?, ?)', (user1_id, user2_id))
    else:
        c.execute('DELETE FROM blocked_users WHERE blocker_id=? AND blocked_id=?', (user1_id, user2_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': f'User {action}ed successfully'})

@app.route('/remove-friend', methods=['POST'])
def remove_friend():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json()
    friend_username = data.get('username')
    
    if not friend_username:
        return jsonify({'success': False, 'message': 'Username is required'}), 400
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Get friend's user ID
    c.execute('SELECT id FROM users WHERE username=?', (friend_username,))
    friend = c.fetchone()
    
    if not friend:
        conn.close()
        return jsonify({'success': False, 'message': 'User not found'})
    
    friend_id = friend[0]
    my_id = session['user_id']
    
    # Remove friendship (both directions)
    c.execute('DELETE FROM friend_requests WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?) AND status="accepted"', 
              (my_id, friend_id, friend_id, my_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Friend removed successfully'})

@app.route('/users/blocked-status')
def user_blocked_status():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'User ID required'}), 400
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('SELECT 1 FROM blocked_users WHERE blocker_id=? AND blocked_id=?', (session['user_id'], user_id))
    is_blocked = c.fetchone() is not None
    conn.close()
    
    return jsonify({'success': True, 'is_blocked': is_blocked})

@app.route('/get-profile-picture')
def get_profile_picture():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('SELECT profile_picture FROM users WHERE id=?', (session['user_id'],))
    user = c.fetchone()
    conn.close()
    
    if user and user[0]:
        return jsonify({'success': True, 'profile_picture': user[0]})
    else:
        return jsonify({'success': True, 'profile_picture': None})

@app.route('/auth')
def auth():
    return render_template('login_and_register.html')

@app.route('/sw.js')
def service_worker():
    return '', 204

# Enhanced Communication Features

# Voice Messages
@app.route('/voice-message/upload', methods=['POST'])
def upload_voice_message():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json()
    audio_data = data.get('audio_data')
    duration = data.get('duration', 0)
    receiver_id = data.get('receiver_id')
    
    if not audio_data or not receiver_id:
        return jsonify({'success': False, 'message': 'Audio data and receiver required'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Create message entry
    c.execute('''
        INSERT INTO messages (sender_id, receiver_id, content, message_type)
        VALUES (?, ?, ?, 'voice')
    ''', (session['user_id'], receiver_id, '[Voice Message]'))
    message_id = c.lastrowid
    
    # Store voice data
    c.execute('''
        INSERT INTO voice_messages (message_id, audio_data, duration)
        VALUES (?, ?, ?)
    ''', (message_id, audio_data, duration))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message_id': message_id})

# Message Reactions
@app.route('/messages/react', methods=['POST'])
def react_to_message():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json()
    message_id = data.get('message_id')
    reaction_type = data.get('reaction_type')  # '👍', '❤️', '😂', '😮', '😢', '😡'
    
    if not message_id or not reaction_type:
        return jsonify({'success': False, 'message': 'Message ID and reaction type required'})
    
    # Validate reaction type
    allowed_reactions = ['👍', '❤️', '😂', '😮', '😢', '😡']
    if reaction_type not in allowed_reactions:
        return jsonify({'success': False, 'message': 'Invalid reaction type'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if message exists and user has access to it
    c.execute('''
        SELECT sender_id, receiver_id FROM messages WHERE id=?
    ''', (message_id,))
    message = c.fetchone()
    
    if not message:
        conn.close()
        return jsonify({'success': False, 'message': 'Message not found'})
    
    sender_id, receiver_id = message
    user_id = session['user_id']
    
    # Check if user is part of this conversation
    if user_id not in [sender_id, receiver_id]:
        conn.close()
        return jsonify({'success': False, 'message': 'Access denied'})
    
    # Remove any existing reaction from this user on this message
    c.execute('DELETE FROM message_reactions WHERE message_id=? AND user_id=?',
              (message_id, user_id))
    
    # Check if user is trying to remove the same reaction (toggle off)
    c.execute('SELECT id FROM message_reactions WHERE message_id=? AND user_id=? AND reaction_type=?',
              (message_id, user_id, reaction_type))
    
    action = 'removed'
    if not c.fetchone():  # No existing reaction, so add it
        c.execute('INSERT INTO message_reactions (message_id, user_id, reaction_type) VALUES (?, ?, ?)',
                  (message_id, user_id, reaction_type))
        action = 'added'
    
    conn.commit()
    
    # Get updated reaction counts
    c.execute('''
        SELECT reaction_type, COUNT(*) as count
        FROM message_reactions 
        WHERE message_id = ?
        GROUP BY reaction_type
    ''', (message_id,))
    reactions = c.fetchall()
    
    # Get user's current reaction
    c.execute('SELECT reaction_type FROM message_reactions WHERE message_id=? AND user_id=?',
              (message_id, user_id))
    user_reaction = c.fetchone()
    
    conn.close()
    
    # Emit real-time update to both users
    reaction_data = {
        'message_id': message_id,
        'reactions': {r[0]: r[1] for r in reactions},
        'user_reaction': user_reaction[0] if user_reaction else None,
        'action': action,
        'reaction_type': reaction_type,
        'user_id': user_id
    }
    
    try:
        socketio.emit('message_reaction_update', reaction_data, to=str(sender_id))
        socketio.emit('message_reaction_update', reaction_data, to=str(receiver_id))
    except Exception as e:
        print(f"Socket emit error: {e}")
    
    return jsonify({
        'success': True, 
        'action': action,
        'reactions': {r[0]: r[1] for r in reactions},
        'user_reaction': user_reaction[0] if user_reaction else None
    })



# Message Threading (Reply)
@app.route('/messages/reply', methods=['POST'])
def reply_to_message():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json()
    reply_to_id = data.get('reply_to_id')
    receiver_id = data.get('receiver_id')
    content = data.get('content')
    
    if not all([reply_to_id, receiver_id, content]):
        return jsonify({'success': False, 'message': 'All fields required'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    c.execute('''
        INSERT INTO messages (sender_id, receiver_id, content, reply_to_id)
        VALUES (?, ?, ?, ?)
    ''', (session['user_id'], receiver_id, content, reply_to_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Reply sent'})

# Message Forwarding
@app.route('/messages/forward', methods=['POST'])
def forward_message():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json()
    message_id = data.get('message_id')
    receiver_ids = data.get('receiver_ids', [])
    
    if not message_id or not receiver_ids:
        return jsonify({'success': False, 'message': 'Message ID and receivers required'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Get original message
    c.execute('SELECT content, message_type, file_url FROM messages WHERE id=?', (message_id,))
    original = c.fetchone()
    
    if not original:
        conn.close()
        return jsonify({'success': False, 'message': 'Message not found'})
    
    # Forward to each receiver
    for receiver_id in receiver_ids:
        c.execute('''
            INSERT INTO messages (sender_id, receiver_id, content, message_type, file_url, forwarded_from)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], receiver_id, original[0], original[1], original[2], message_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': f'Message forwarded to {len(receiver_ids)} users'})

# Message Search
@app.route('/messages/search')
def search_messages():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify({'success': False, 'message': 'Search query required'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    c.execute('''
        SELECT m.id, m.content, m.created_at, u.username as sender_name
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = ? OR m.receiver_id = ?)
        AND m.content LIKE ?
        ORDER BY m.created_at DESC
        LIMIT 50
    ''', (session['user_id'], session['user_id'], f'%{query}%'))
    
    results = c.fetchall()
    conn.close()
    
    return jsonify({
        'success': True,
        'results': [{
            'id': r[0],
            'content': r[1],
            'created_at': r[2],
            'sender_name': r[3]
        } for r in results]
    })

# User Experience Improvements

# Theme Toggle
@app.route('/user/theme', methods=['POST'])
def update_theme():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json()
    theme = data.get('theme', 'light')
    
    if theme not in ['light', 'dark']:
        return jsonify({'success': False, 'message': 'Invalid theme'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('UPDATE users SET theme=? WHERE id=?', (theme, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'theme': theme})

@app.route('/user/theme')
def get_theme():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('SELECT theme FROM users WHERE id=?', (session['user_id'],))
    result = c.fetchone()
    conn.close()
    
    return jsonify({'success': True, 'theme': result[0] if result else 'light'})

# Online Status & Presence
@app.route('/user/status', methods=['POST'])
def update_online_status():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json()
    status = data.get('status', 'online')  # online, away, busy, offline
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('UPDATE users SET online_status=?, last_seen=CURRENT_TIMESTAMP WHERE id=?',
              (status, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'status': status})

@app.route('/user/presence/<int:user_id>')
def get_user_presence(user_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('SELECT online_status, last_seen FROM users WHERE id=?', (user_id,))
    result = c.fetchone()
    conn.close()
    
    if result:
        return jsonify({
            'success': True,
            'online_status': result[0],
            'last_seen': result[1],
            'is_online': user_id in ONLINE_USERS
        })
    
    return jsonify({'success': False, 'message': 'User not found'})

# Typing Indicators
@socketio.on('typing_start')
def handle_typing_start(data):
    user_id = session.get('user_id')
    chat_id = data.get('chat_id')
    chat_type = data.get('chat_type', 'user')
    
    if user_id and chat_id:
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        c.execute('''
            INSERT OR REPLACE INTO typing_indicators (user_id, chat_id, chat_type, is_typing, updated_at)
            VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)
        ''', (user_id, chat_id, chat_type))
        conn.commit()
        conn.close()
        
        emit('user_typing', {
            'user_id': user_id,
            'chat_id': chat_id,
            'chat_type': chat_type,
            'is_typing': True
        }, to=str(chat_id) if chat_type == 'user' else f'group_{chat_id}')

@socketio.on('typing_stop')
def handle_typing_stop(data):
    user_id = session.get('user_id')
    chat_id = data.get('chat_id')
    chat_type = data.get('chat_type', 'user')
    
    if user_id and chat_id:
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        c.execute('''
            UPDATE typing_indicators SET is_typing=0, updated_at=CURRENT_TIMESTAMP
            WHERE user_id=? AND chat_id=? AND chat_type=?
        ''', (user_id, chat_id, chat_type))
        conn.commit()
        conn.close()
        
        emit('user_typing', {
            'user_id': user_id,
            'chat_id': chat_id,
            'chat_type': chat_type,
            'is_typing': False
        }, to=str(chat_id) if chat_type == 'user' else f'group_{chat_id}')

# Message Templates
@app.route('/templates', methods=['GET', 'POST'])
def message_templates():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    if request.method == 'POST':
        data = request.get_json()
        name = data.get('name')
        content = data.get('content')
        
        if not name or not content:
            return jsonify({'success': False, 'message': 'Name and content required'})
        
        c.execute('INSERT INTO message_templates (user_id, name, content) VALUES (?, ?, ?)',
                  (session['user_id'], name, content))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Template saved'})
    
    else:
        c.execute('SELECT id, name, content, created_at FROM message_templates WHERE user_id=?',
                  (session['user_id'],))
        templates = c.fetchall()
        conn.close()
        
        return jsonify({
            'success': True,
            'templates': [{
                'id': t[0],
                'name': t[1],
                'content': t[2],
                'created_at': t[3]
            } for t in templates]
        })

# Scheduled Messages
@app.route('/messages/schedule', methods=['POST'])
def schedule_message():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json()
    receiver_id = data.get('receiver_id')
    content = data.get('content')
    scheduled_at = data.get('scheduled_at')
    
    if not all([receiver_id, content, scheduled_at]):
        return jsonify({'success': False, 'message': 'All fields required'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('''
        INSERT INTO scheduled_messages (sender_id, receiver_id, content, scheduled_at)
        VALUES (?, ?, ?, ?)
    ''', (session['user_id'], receiver_id, content, scheduled_at))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Message scheduled'})

# Advanced Group Features

# Group Announcements
@app.route('/groups/<int:group_id>/announcements', methods=['GET', 'POST'])
def group_announcements(group_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check membership
    c.execute('SELECT role FROM group_members WHERE group_id=? AND user_id=?', (group_id, session['user_id']))
    member = c.fetchone()
    if not member:
        conn.close()
        return jsonify({'success': False, 'message': 'Not a group member'}), 403
    
    if request.method == 'POST':
        # Only admins can create announcements
        if member[0] not in ['admin', 'creator']:
            conn.close()
            return jsonify({'success': False, 'message': 'Only admins can create announcements'}), 403
        
        data = request.get_json()
        content = data.get('content')
        
        if not content:
            return jsonify({'success': False, 'message': 'Content required'})
        
        c.execute('INSERT INTO group_announcements (group_id, user_id, content) VALUES (?, ?, ?)',
                  (group_id, session['user_id'], content))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Announcement created'})
    
    else:
        c.execute('''
            SELECT ga.id, ga.content, ga.created_at, u.username
            FROM group_announcements ga
            JOIN users u ON ga.user_id = u.id
            WHERE ga.group_id = ? AND ga.pinned = 1
            ORDER BY ga.created_at DESC
        ''', (group_id,))
        announcements = c.fetchall()
        conn.close()
        
        return jsonify({
            'success': True,
            'announcements': [{                          
                'id': a[0],
                'content': a[1],
                'created_at': a[2],
                'author': a[3]
            } for a in announcements]
        })

# Group Events
@app.route('/groups/<int:group_id>/events', methods=['GET', 'POST'])
def group_events(group_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check membership
    c.execute('SELECT role FROM group_members WHERE group_id=? AND user_id=?', (group_id, session['user_id']))
    if not c.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'Not a group member'}), 403
    
    if request.method == 'POST':
        data = request.get_json()
        title = data.get('title')
        description = data.get('description', '')
        event_date = data.get('event_date')
        location = data.get('location', '')
        
        if not title or not event_date:
            return jsonify({'success': False, 'message': 'Title and date required'})
        
        c.execute('''
            INSERT INTO group_events (group_id, creator_id, title, description, event_date, location)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (group_id, session['user_id'], title, description, event_date, location))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Event created'})
    
    else:
        c.execute('''
            SELECT ge.id, ge.title, ge.description, ge.event_date, ge.location, u.username
            FROM group_events ge
            JOIN users u ON ge.creator_id = u.id
            WHERE ge.group_id = ?
            ORDER BY ge.event_date ASC
        ''', (group_id,))
        events = c.fetchall()
        conn.close()
        
        return jsonify({
            'success': True,
            'events': [{
                'id': e[0],
                'title': e[1],
                'description': e[2],
                'event_date': e[3],
                'location': e[4],
                'creator': e[5]
            } for e in events]
        })

# Group Polls
@app.route('/groups/<int:group_id>/polls', methods=['GET', 'POST'])
def group_polls(group_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check membership
    c.execute('SELECT role FROM group_members WHERE group_id=? AND user_id=?', (group_id, session['user_id']))
    if not c.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'Not a group member'}), 403
    
    if request.method == 'POST':
        data = request.get_json()
        question = data.get('question')
        options = data.get('options', [])
        expires_at = data.get('expires_at')
        
        if not question or len(options) < 2:
            return jsonify({'success': False, 'message': 'Question and at least 2 options required'})
        
        import json
        c.execute('''
            INSERT INTO group_polls (group_id, creator_id, question, options, expires_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (group_id, session['user_id'], question, json.dumps(options), expires_at))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Poll created'})
    
    else:
        c.execute('''
            SELECT gp.id, gp.question, gp.options, gp.expires_at, u.username
            FROM group_polls gp
            JOIN users u ON gp.creator_id = u.id
            WHERE gp.group_id = ?
            ORDER BY gp.created_at DESC
        ''', (group_id,))
        polls = c.fetchall()
        
        import json
        poll_data = []
        for poll in polls:
            # Get vote counts
            c.execute('SELECT option_index, COUNT(*) FROM group_poll_votes WHERE poll_id=? GROUP BY option_index',
                      (poll[0],))
            votes = dict(c.fetchall())
            
            poll_data.append({
                'id': poll[0],
                'question': poll[1],
                'options': json.loads(poll[2]),
                'expires_at': poll[3],
                'creator': poll[4],
                'votes': votes
            })
        
        conn.close()
        return jsonify({'success': True, 'polls': poll_data})

@app.route('/polls/<int:poll_id>/vote', methods=['POST'])
def vote_poll(poll_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    data = request.get_json()
    option_index = data.get('option_index')
    
    if option_index is None:
        return jsonify({'success': False, 'message': 'Option index required'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # Check if poll exists and user is group member
    c.execute('''
        SELECT gp.group_id FROM group_polls gp
        JOIN group_members gm ON gp.group_id = gm.group_id
        WHERE gp.id = ? AND gm.user_id = ?
    ''', (poll_id, session['user_id']))
    
    if not c.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'Poll not found or access denied'}), 403
    
    # Vote (replace existing vote)
    c.execute('DELETE FROM group_poll_votes WHERE poll_id=? AND user_id=?', (poll_id, session['user_id']))
    c.execute('INSERT INTO group_poll_votes (poll_id, user_id, option_index) VALUES (?, ?, ?)',
              (poll_id, session['user_id'], option_index))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Vote recorded'})

# User Stories
@app.route('/stories', methods=['GET', 'POST'])
def user_stories():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    if request.method == 'POST':
        data = request.get_json()
        content = data.get('content')
        media_type = data.get('media_type', 'text')
        media_url = data.get('media_url')
        
        if not content:
            return jsonify({'success': False, 'message': 'Content required'})
        
        # Stories expire after 24 hours
        from datetime import datetime, timedelta
        expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
        
        c.execute('''
            INSERT INTO user_stories (user_id, content, media_type, media_url, expires_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (session['user_id'], content, media_type, media_url, expires_at))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Story posted'})
    
    else:
        # Get stories from friends
        c.execute('''
            SELECT DISTINCT us.id, us.content, us.media_type, us.media_url, us.created_at, u.username
            FROM user_stories us
            JOIN users u ON us.user_id = u.id
            JOIN (
                SELECT CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END AS friend_id
                FROM friend_requests
                WHERE (sender_id = ? OR receiver_id = ?) AND status = 'accepted'
                UNION
                SELECT ? AS friend_id
            ) f ON us.user_id = f.friend_id
            WHERE us.expires_at > CURRENT_TIMESTAMP
            ORDER BY us.created_at DESC
        ''', (session['user_id'], session['user_id'], session['user_id'], session['user_id']))
        
        stories = c.fetchall()
        conn.close()
        
        return jsonify({
            'success': True,
            'stories': [{
                'id': s[0],
                'content': s[1],
                'media_type': s[2],
                'media_url': s[3],
                'created_at': s[4],
                'username': s[5]
            } for s in stories]
        })

# Privacy Settings
@app.route('/user/privacy', methods=['GET', 'POST'])
def privacy_settings():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    if request.method == 'POST':
        data = request.get_json()
        import json
        
        c.execute('UPDATE users SET privacy_settings=? WHERE id=?',
                  (json.dumps(data), session['user_id']))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Privacy settings updated'})
    
    else:
        c.execute('SELECT privacy_settings FROM users WHERE id=?', (session['user_id'],))
        result = c.fetchone()
        conn.close()
        
        import json
        settings = json.loads(result[0]) if result and result[0] else {}
        return jsonify({'success': True, 'settings': settings})

# Notification Settings
@app.route('/user/notifications', methods=['GET', 'POST'])
def notification_settings():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    if request.method == 'POST':
        data = request.get_json()
        import json
        
        c.execute('UPDATE users SET notification_settings=? WHERE id=?',
                  (json.dumps(data), session['user_id']))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Notification settings updated'})
    
    else:
        c.execute('SELECT notification_settings FROM users WHERE id=?', (session['user_id'],))
        result = c.fetchone()
        conn.close()
        
        import json
        settings = json.loads(result[0]) if result and result[0] else {}
        return jsonify({'success': True, 'settings': settings})

# Extended User Profile
@app.route('/user/profile', methods=['GET', 'POST'])
def user_profile():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    if request.method == 'POST':
        data = request.get_json()
        bio = data.get('bio', '')
        interests = data.get('interests', '')
        
        c.execute('UPDATE users SET bio=?, interests=? WHERE id=?',
                  (bio, interests, session['user_id']))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Profile updated'})
    
    else:
        c.execute('SELECT username, email, bio, interests, profile_picture, created_at FROM users WHERE id=?',
                  (session['user_id'],))
        result = c.fetchone()
        conn.close()
        
        if result:
            return jsonify({
                'success': True,
                'profile': {
                    'username': result[0],
                    'email': result[1],
                    'bio': result[2],
                    'interests': result[3],
                    'profile_picture': result[4],
                    'member_since': result[5]
                }
            })
        
        return jsonify({'success': False, 'message': 'Profile not found'})

# Chat Export
@app.route('/messages/export')
def export_chat():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    other_user_id = request.args.get('with_user_id')
    if not other_user_id:
        return jsonify({'success': False, 'message': 'User ID required'})
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    c.execute('''
        SELECT m.content, m.created_at, u.username as sender
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE ((m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?))
        ORDER BY m.created_at ASC
    ''', (session['user_id'], other_user_id, other_user_id, session['user_id']))
    
    messages = c.fetchall()
    conn.close()
    
    # Format as text
    export_text = "\n".join([f"[{msg[1]}] {msg[2]}: {msg[0]}" for msg in messages])
    
    from flask import Response
    return Response(
        export_text,
        mimetype='text/plain',
        headers={'Content-Disposition': 'attachment; filename="chat_export.txt"'}
    )

# Auto-Reply System
@app.route('/user/auto-reply', methods=['GET', 'POST'])
def auto_reply():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    if request.method == 'POST':
        data = request.get_json()
        enabled = data.get('enabled', False)
        message = data.get('message', '')
        
        import json
        settings = {'enabled': enabled, 'message': message}
        
        c.execute('UPDATE users SET notification_settings=? WHERE id=?',
                  (json.dumps(settings), session['user_id']))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Auto-reply updated'})
    
    else:
        c.execute('SELECT notification_settings FROM users WHERE id=?', (session['user_id'],))
        result = c.fetchone()
        conn.close()
        
        import json
        settings = json.loads(result[0]) if result and result[0] else {}
        return jsonify({'success': True, 'auto_reply': settings.get('auto_reply', {})})

if __name__ == '__main__':
    init_db()
    port = int(os.getenv('PORT', 5001))
    debug = os.getenv('FLASK_ENV') == 'development'
    socketio.run(app, host='0.0.0.0', port=port, debug=debug)

# Message Reactions Routes
@app.route('/react-message', methods=['POST'])
def react_message():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    data = request.get_json()
    message_id = data.get('message_id')
    reaction = data.get('reaction')
    
    if not message_id or not reaction:
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    try:
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        
        # Check if message exists and user has access to it
        c.execute('''SELECT sender_id, receiver_id FROM messages WHERE id = ?''', (message_id,))
        message = c.fetchone()
        
        if not message:
            return jsonify({'success': False, 'message': 'Message not found'}), 404
        
        sender_id, receiver_id = message
        user_id = session['user_id']
        
        # Check if user is part of the conversation
        if user_id not in [sender_id, receiver_id]:
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        
        # Insert or update reaction
        c.execute('''INSERT OR REPLACE INTO message_reactions 
                     (message_id, user_id, reaction) VALUES (?, ?, ?)''',
                  (message_id, user_id, reaction))
        
        conn.commit()
        
        c.execute('''SELECT reaction, COUNT(*) as count, 
                     GROUP_CONCAT(u.username) as users
                     FROM message_reactions mr
                     JOIN users u ON mr.user_id = u.id
                     WHERE mr.message_id = ?
                     GROUP BY reaction''', (message_id,))
        
        reactions = {}
        for row in c.fetchall():
            emoji, count, users = row
            reactions[emoji] = {
                'count': count,
                'users': users.split(',') if users else []
            }
        
        conn.close()
        
        socketio.emit('reaction_update', {
            'message_id': message_id,
            'reactions': reactions,
            'user_id': user_id,
            'reaction': reaction
        }, room=f'user_{sender_id}')
        
        if sender_id != receiver_id:
            socketio.emit('reaction_update', {
                'message_id': message_id,
                'reactions': reactions,
                'user_id': user_id,
                'reaction': reaction
            }, room=f'user_{receiver_id}')
        
        return jsonify({
            'success': True,
            'reactions': reactions
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/remove-reaction', methods=['POST'])
def remove_reaction():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    data = request.get_json()
    message_id = data.get('message_id')
    
    if not message_id:
        return jsonify({'success': False, 'message': 'Missing message_id'}), 400
    
    try:
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        
        c.execute('''DELETE FROM message_reactions 
                     WHERE message_id = ? AND user_id = ?''',
                  (message_id, session['user_id']))
        
        conn.commit()
        
        c.execute('''SELECT reaction, COUNT(*) as count,
                     GROUP_CONCAT(u.username) as users
                     FROM message_reactions mr
                     JOIN users u ON mr.user_id = u.id
                     WHERE mr.message_id = ?
                     GROUP BY reaction''', (message_id,))
        
        reactions = {}
        for row in c.fetchall():
            emoji, count, users = row
            reactions[emoji] = {
                'count': count,
                'users': users.split(',') if users else []
            }
        
        c.execute('''SELECT sender_id, receiver_id FROM messages WHERE id = ?''', (message_id,))
        message = c.fetchone()
        
        conn.close()
        
        if message:
            sender_id, receiver_id = message
            
            socketio.emit('reaction_removed', {
                'message_id': message_id,
                'reactions': reactions,
                'user_id': session['user_id']
            }, room=f'user_{sender_id}')
            
            if sender_id != receiver_id:
                socketio.emit('reaction_removed', {
                    'message_id': message_id,
                    'reactions': reactions,
                    'user_id': session['user_id']
                }, room=f'user_{receiver_id}')
        
        return jsonify({
            'success': True,
            'reactions': reactions
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/get-message-reactions/<int:message_id>')
def get_message_reactions(message_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    try:
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        
        c.execute('''SELECT reaction, COUNT(*) as count,
                     GROUP_CONCAT(u.username) as users
                     FROM message_reactions mr
                     JOIN users u ON mr.user_id = u.id
                     WHERE mr.message_id = ?
                     GROUP BY reaction''', (message_id,))
        
        reactions = {}
        for row in c.fetchall():
            emoji, count, users = row
            reactions[emoji] = {
                'count': count,
                'users': users.split(',') if users else []
            }
        
        conn.close()
        
        return jsonify({
            'success': True,
            'reactions': reactions
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@socketio.on('add_reaction')
def handle_add_reaction(data):
    if 'user_id' not in session:
        return
    
    message_id = data.get('message_id')
    reaction = data.get('reaction')
    
    if not message_id or not reaction:
        return
    
    try:
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        
        c.execute('''INSERT OR REPLACE INTO message_reactions 
                     (message_id, user_id, reaction) VALUES (?, ?, ?)''',
                  (message_id, session['user_id'], reaction))
        
        conn.commit()
        
        c.execute('''SELECT reaction, COUNT(*) as count,
                     GROUP_CONCAT(u.username) as users
                     FROM message_reactions mr
                     JOIN users u ON mr.user_id = u.id
                     WHERE mr.message_id = ?
                     GROUP BY reaction''', (message_id,))
        
        reactions = {}
        for row in c.fetchall():
            emoji, count, users = row
            reactions[emoji] = {
                'count': count,
                'users': users.split(',') if users else []
            }
        
        c.execute('''SELECT sender_id, receiver_id FROM messages WHERE id = ?''', (message_id,))
        message = c.fetchone()
        
        conn.close()
        
        if message:
            sender_id, receiver_id = message
            
            emit('reaction_update', {
                'message_id': message_id,
                'reactions': reactions,
                'user_id': session['user_id'],
                'reaction': reaction
            }, room=f'user_{sender_id}')
            
            if sender_id != receiver_id:
                emit('reaction_update', {
                    'message_id': message_id,
                    'reactions': reactions,
                    'user_id': session['user_id'],
                    'reaction': reaction
                }, room=f'user_{receiver_id}')
        
    except Exception as e:
        emit('error', {'message': str(e)})

@socketio.on('remove_reaction')
def handle_remove_reaction(data):
    if 'user_id' not in session:
        return
    
    message_id = data.get('message_id')
    
    if not message_id:
        return
    
    try:
        conn = sqlite3.connect(get_db_path())
        c = conn.cursor()
        
        c.execute('''DELETE FROM message_reactions 
                     WHERE message_id = ? AND user_id = ?''',
                  (message_id, session['user_id']))
        
        conn.commit()
        
        c.execute('''SELECT reaction, COUNT(*) as count,
                     GROUP_CONCAT(u.username) as users
                     FROM message_reactions mr
                     JOIN users u ON mr.user_id = u.id
                     WHERE mr.message_id = ?
                     GROUP BY reaction''', (message_id,))
        
        reactions = {}
        for row in c.fetchall():
            emoji, count, users = row
            reactions[emoji] = {
                'count': count,
                'users': users.split(',') if users else []
            }
        
        c.execute('''SELECT sender_id, receiver_id FROM messages WHERE id = ?''', (message_id,))
        message = c.fetchone()
        
        conn.close()
        
        if message:
            sender_id, receiver_id = message
            
            emit('reaction_removed', {
                'message_id': message_id,
                'reactions': reactions,
                'user_id': session['user_id']
            }, room=f'user_{sender_id}')
            
            if sender_id != receiver_id:
                emit('reaction_removed', {
                    'message_id': message_id,
                    'reactions': reactions,
                    'user_id': session['user_id']
                }, room=f'user_{receiver_id}')
        
    except Exception as e:
        emit('error', {'message': str(e)})
