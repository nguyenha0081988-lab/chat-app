# server.py

import eventlet
eventlet.monkey_patch()

import os, click
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
UPLOAD_FOLDER = os.path.join(basedir, 'uploads');
if not os.path.exists(UPLOAD_FOLDER): os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app); login_manager = LoginManager(app); socketio = SocketIO(app, cors_allowed_origins="*")
online_users = {}

# --- CÁC MODEL CƠ SỞ DỮ LIỆU ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True); username = db.Column(db.String(80), unique=True, nullable=False); password_hash = db.Column(db.String(256)); is_admin = db.Column(db.Boolean, default=False, nullable=False); files = db.relationship('File', backref='owner', lazy=True, cascade="all, delete-orphan")
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True); filename = db.Column(db.String(255), nullable=False); user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# MỚI: Model để lưu tin nhắn
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])

@app.before_request
def create_tables():
    with app.app_context():
        inspector = inspect(db.engine)
        if not inspector.has_table("message"): # Kiểm tra bảng mới
            db.create_all()
            print("Database tables (including message) created.")
# ... (Phần còn lại giữ nguyên)

# --- API LẤY LỊCH SỬ CHAT (MỚI) ---
@app.route('/history/<int:partner_id>')
@login_required
def get_history(partner_id):
    messages = db.session.query(Message).filter(
        or_(
            (Message.sender_id == current_user.id) & (Message.recipient_id == partner_id),
            (Message.sender_id == partner_id) & (Message.recipient_id == current_user.id)
        )
    ).order_by(Message.timestamp.asc()).all()

    history = [
        {'sender': msg.sender.username, 'message': msg.content, 'timestamp': msg.timestamp.isoformat()}
        for msg in messages
    ]
    return jsonify(history)

# --- CÁC SỰ KIỆN SOCKET.IO ---
@socketio.on('private_message')
def handle_private_message(data):
    recipient_id = data['recipient_id']; message_content = data['message']
    
    # MỚI: Lưu tin nhắn vào CSDL
    new_message = Message(
        sender_id=current_user.id,
        recipient_id=recipient_id,
        content=message_content
    )
    db.session.add(new_message)
    db.session.commit()
    
    recipient_sid = online_users.get(recipient_id)
    if recipient_sid:
        emit('message_from_server', {'sender': current_user.username, 'message': message_content}, room=recipient_sid)
    emit('message_from_server', {'sender': current_user.username, 'message': message_content}, room=request.sid)

# ... (Toàn bộ các API và hàm khác giữ nguyên như cũ) ...
@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))
@app.route('/')
def index(): return "Backend server for the application is running!"
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json(); is_first_user = User.query.first() is None; new_user = User(username=data.get('username'))
    new_user.set_password(data.get('password')); 
    if is_first_user: new_user.is_admin = True
    db.session.add(new_user); db.session.commit()
    message = "Đăng ký thành công!" + (" Tài khoản của bạn là Admin." if is_first_user else "")
    return jsonify({'message': message}), 201
if __name__ == '__main__': socketio.run(app, debug=True, port=5000)
