# server.py

import eventlet
eventlet.monkey_patch()

import os, click, cloudinary, cloudinary.uploader, cloudinary.api
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_from_directory
from flask.cli import with_appcontext
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, or_
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from functools import wraps
from flask_socketio import SocketIO, emit

# --- KHỞI TẠO VÀ CẤU HÌNH ---
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-fallback-secret-key-for-development')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app); login_manager = LoginManager(app); socketio = SocketIO(app, cors_allowed_origins="*")
online_users = {}
cloudinary.config(cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME'), api_key=os.environ.get('CLOUDINARY_API_KEY'), api_secret=os.environ.get('CLOUDINARY_API_SECRET'))

# --- DECORATOR, MODELS, USER_LOADER ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin: return jsonify({'message': 'Yêu cầu quyền Admin!'}), 403
        return f(*args, **kwargs)
    return decorated_function
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True); username = db.Column(db.String(80), unique=True, nullable=False); password_hash = db.Column(db.String(256)); is_admin = db.Column(db.Boolean, default=False, nullable=False); avatar_url = db.Column(db.String(256), nullable=True)
    files = db.relationship('File', backref='owner', lazy=True, cascade="all, delete-orphan")
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender_user', lazy=True, cascade="all, delete-orphan")
    received_messages = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient_user', lazy=True, cascade="all, delete-orphan")
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True); filename = db.Column(db.String(255), nullable=False); public_id = db.Column(db.String(255), nullable=False, unique=True); user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True); content = db.Column(db.Text, nullable=False); timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    # SỬA LỖI: Bổ sung lại các dòng relationship bị thiếu
    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])
@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

@app.before_request
def create_tables_and_admin():
    with app.app_context():
        db.create_all()
        if User.query.first() is None:
            admin_user = os.environ.get('DEFAULT_ADMIN_USER', 'admin'); admin_pass = os.environ.get('DEFAULT_ADMIN_PASSWORD')
            if admin_pass and User.query.filter_by(username=admin_user).first() is None:
                default_admin = User(username=admin_user, is_admin=True); default_admin.set_password(admin_pass)
                db.session.add(default_admin); db.session.commit(); print(f"Default admin user '{admin_user}' created.")

# --- CÁC ĐƯỜNG DẪN API (ROUTES) ---
# ... (Toàn bộ các API và hàm Socket.IO giữ nguyên như cũ) ...
@app.route('/')
def index(): return "Backend server for the application is running!"
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(); username, password = data.get('username'), data.get('password')
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        login_user(user)
        return jsonify({'message': 'Đăng nhập thành công!', 'user_id': user.id, 'username': user.username, 'is_admin': user.is_admin, 'avatar_url': user.avatar_url})
    return jsonify({'message': 'Sai tên đăng nhập hoặc mật khẩu!'}), 401
@app.route('/history/<int:partner_id>', methods=['GET'])
@login_required
def get_history(partner_id):
    messages_to_mark_read = db.session.query(Message).filter((Message.sender_id == partner_id) & (Message.recipient_id == current_user.id) & (Message.is_read == False))
    message_ids_to_update = [msg.id for msg in messages_to_mark_read.all()]
    messages_to_mark_read.update({Message.is_read: True}); db.session.commit()
    all_messages = db.session.query(Message).filter(or_((Message.sender_id == current_user.id) & (Message.recipient_id == partner_id), (Message.sender_id == partner_id) & (Message.recipient_id == current_user.id))).order_by(Message.timestamp.asc()).all()
    history = [{'id': msg.id, 'sender': msg.sender.username if msg.sender else "N/A", 'message': msg.content, 'is_read': msg.is_read} for msg in all_messages]
    partner_sid = online_users.get(partner_id)
    if partner_sid and message_ids_to_update:
        emit('messages_seen', {'ids': message_ids_to_update}, room=partner_sid)
    return jsonify(history)
# ... (và các API khác)

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
