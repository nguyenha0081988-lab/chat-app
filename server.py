# server.py

# Tối ưu cho eventlet: Các dòng này PHẢI nằm ở trên cùng
import eventlet
eventlet.monkey_patch()

# Các thư viện khác
import os, click
from flask import Flask, request, jsonify, send_from_directory
from flask.cli import with_appcontext
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from functools import wraps
from flask_socketio import SocketIO, emit

# --- KHỞI TẠO VÀ CẤU HÌNH ---
# ... (Giữ nguyên như cũ) ...
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

# --- DECORATOR, MODELS, USER_LOADER ---
# ... (Toàn bộ phần này giữ nguyên như cũ) ...
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin: return jsonify({'message': 'Admin access required!'}), 403
        return f(*args, **kwargs)
    return decorated_function
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True); username = db.Column(db.String(80), unique=True, nullable=False); password_hash = db.Column(db.String(128)); is_admin = db.Column(db.Boolean, default=False, nullable=False); files = db.relationship('File', backref='owner', lazy=True, cascade="all, delete-orphan")
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True); filename = db.Column(db.String(255), nullable=False); user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

# --- CÁC ĐƯỜNG DẪN API (ROUTES) ---
# ... (Các API cũ giữ nguyên) ...
@app.route('/')
def index(): return "Backend server for the application is running!"
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json(); username, password = data.get('username'), data.get('password')
    if User.query.filter_by(username=username).first(): return jsonify({'message': 'Tên đăng nhập đã tồn tại!'}), 400
    new_user = User(username=username); new_user.set_password(password)
    db.session.add(new_user); db.session.commit(); return jsonify({'message': 'Đăng ký người dùng thành công!'}), 201
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(); username, password = data.get('username'), data.get('password')
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        login_user(user)
        return jsonify({'message': 'Đăng nhập thành công!', 'user_id': user.id, 'username': user.username, 'is_admin': user.is_admin})
    return jsonify({'message': 'Sai tên đăng nhập hoặc mật khẩu!'}), 401
# ... (Các API file, online-users giữ nguyên) ...

# --- API CHO ADMIN (ĐÃ NÂNG CẤP) ---
@app.route('/admin/users', methods=['GET'])
@login_required
@admin_required
def get_all_users():
    users = User.query.all()
    return jsonify([{'id': u.id, 'username': u.username, 'is_admin': u.is_admin} for u in users])

# MỚI: API cho Admin thêm người dùng
@app.route('/admin/users', methods=['POST'])
@login_required
@admin_required
def admin_add_user():
    data = request.get_json()
    username, password = data.get('username'), data.get('password')
    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400
    
    new_user = User(username=username, is_admin=data.get('is_admin', False))
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': f'User {username} created successfully'}), 201

# MỚI: API cho Admin sửa người dùng
@app.route('/admin/users/<int:user_id>', methods=['PUT'])
@login_required
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    
    if 'username' in data and data['username'] != user.username:
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'message': 'Username already exists'}), 400
        user.username = data['username']
        
    if 'password' in data and data['password']:
        user.set_password(data['password'])
        
    if 'is_admin' in data:
        user.is_admin = data['is_admin']
        
    db.session.commit()
    return jsonify({'message': f'User {user.username} updated successfully'})

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    # ... (code giữ nguyên) ...
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.username == current_user.username: return jsonify({'message': 'Không thể tự xóa chính mình'}), 403
    db.session.delete(user_to_delete); db.session.commit()
    return jsonify({'message': f'User {user_to_delete.username} đã bị xóa.'})

# --- SOCKET.IO VÀ CÁC PHẦN CÒN LẠI ---
# ... (Toàn bộ phần còn lại giữ nguyên như cũ) ...
with app.app_context(): db.create_all()
@click.command('make-admin')
@click.argument('username')
@with_appcontext
def make_admin(username):
    user = User.query.filter_by(username=username).first()
    if user: user.is_admin = True; db.session.commit(); print(f"User {username} is now an admin.")
    else: print(f"User {username} not found.")
app.cli.add_command(make_admin)
if __name__ == '__main__': socketio.run(app, debug=True, port=5000)
