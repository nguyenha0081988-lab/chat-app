# server.py

import os
import click
from flask import Flask, request, jsonify, send_from_directory
from flask.cli import with_appcontext
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from functools import wraps
from flask_socketio import SocketIO, emit

# --- KHỞI TẠO VÀ CẤU HÌNH ---
basedir = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(basedir, 'uploads')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mot-cai-khoa-bi-mat-ma-ban-nen-thay-doi'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
login_manager = LoginManager(app)
socketio = SocketIO(app)

online_users = {} # key: user_id, value: session_id

# --- DECORATOR KIỂM TRA ADMIN ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({'message': 'Admin access required!'}), 403
        return f(*args, **kwargs)
    return decorated_function

# --- CÁC MODEL CƠ SỞ DỮ LIỆU ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    files = db.relationship('File', backref='owner', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- CÁC ĐƯỜNG DẪN API (ROUTES) ---
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username, password = data.get('username'), data.get('password')
        if not username or not password:
            return jsonify({'message': 'Tên đăng nhập và mật khẩu là bắt buộc!'}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({'message': 'Tên đăng nhập đã tồn tại!'}), 400
        
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'Đăng ký người dùng thành công!'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Lỗi nội bộ từ server: {e}'}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username, password = data.get('username'), data.get('password')
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        login_user(user)
        return jsonify({
            'message': 'Đăng nhập thành công!',
            'user_id': user.id,
            'username': user.username,
            'is_admin': user.is_admin
        })
    return jsonify({'message': 'Sai tên đăng nhập hoặc mật khẩu!'}), 401

@app.route('/online-users', methods=['GET'])
@login_required
def get_online_users():
    users_info = []
    for user_id in online_users:
        user = User.query.get(user_id)
        if user:
            users_info.append({'id': user.id, 'username': user.username})
    return jsonify({'users': users_info})

# ... (Các API khác giữ nguyên) ...

# --- CÁC SỰ KIỆN SOCKET.IO CHO CHAT ---
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        online_users[current_user.id] = request.sid
        emit('user_status_changed', {'users': get_online_users().json['users']}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated and current_user.id in online_users:
        del online_users[current_user.id]
        emit('user_status_changed', {'users': get_online_users().json['users']}, broadcast=True)

@socketio.on('private_message')
def handle_private_message(data):
    recipient_id = data['recipient_id']
    message = data['message']
    recipient_sid = online_users.get(recipient_id)
    if recipient_sid:
        emit('message_from_server', {'sender': current_user.username, 'message': message}, room=recipient_sid)
        emit('message_from_server', {'sender': current_user.username, 'message': message}, room=request.sid)

# --- LỆNH TÙY CHỈNH & KHỐI CHẠY CHÍNH ---
@click.command('make-admin')
@click.argument('username')
@with_appcontext
def make_admin(username):
    user = User.query.filter_by(username=username).first()
    if user:
        user.is_admin = True
        db.session.commit()
        print(f"User {username} is now an admin.")
    else:
        print(f"User {username} not found.")
app.cli.add_command(make_admin)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True, port=5000)