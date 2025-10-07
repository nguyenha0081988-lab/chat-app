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

# --- CÁC MODEL CƠ SỞ DỮ LIỆU (ĐÃ SỬA ĐỔI) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    files = db.relationship('File', backref='owner', lazy=True) # Không cần cascade ở đây nữa
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    # SỬA ĐỔI: Cho phép user_id là NULL và set ondelete='SET NULL'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    # SỬA ĐỔI: Cho phép sender_id và recipient_id là NULL và set ondelete='SET NULL'
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    
    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])

@app.before_request
def create_tables():
    with app.app_context():
        # Dùng db.create_all() để tự động tạo bảng nếu chưa có
        db.create_all()

# --- API LẤY LỊCH SỬ CHAT (ĐÃ SỬA ĐỔI) ---
@app.route('/history/<int:partner_id>')
@login_required
def get_history(partner_id):
    messages = db.session.query(Message).filter(
        or_((Message.sender_id == current_user.id) & (Message.recipient_id == partner_id), (Message.sender_id == partner_id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    
    history = []
    for msg in messages:
        # SỬA ĐỔI: Kiểm tra xem người gửi có tồn tại không
        sender_name = msg.sender.username if msg.sender else "Người dùng đã bị xóa"
        history.append({'sender': sender_name, 'message': msg.content})
        
    return jsonify(history)

# ... (Toàn bộ các API, hàm, và các phần còn lại giữ nguyên như cũ) ...
# (Phần này quá dài và không thay đổi, tôi sẽ lược bớt để bạn dễ đọc)
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
@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.username == current_user.username: return jsonify({'message': 'Không thể tự xóa chính mình'}), 403
    # Bây giờ lệnh này sẽ chạy được mà không gây lỗi CSDL
    db.session.delete(user_to_delete); db.session.commit()
    return jsonify({'message': f'User {user_to_delete.username} đã bị xóa. Tin nhắn và file của họ được giữ lại.'})
# ... (và các hàm khác)
if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
