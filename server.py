# server.py

# Tối ưu cho eventlet: Các dòng này PHẢI nằm ở trên cùng
import eventlet
eventlet.monkey_patch()

# Các thư viện khác
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
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin: return jsonify({'message': 'Yêu cầu quyền Admin!'}), 403
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
@app.route('/')
def index(): return "Backend server for the application is running!"

# ... (Các API user, chat, admin cũ giữ nguyên) ...
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
@app.route('/online-users', methods=['GET'])
@login_required
def get_online_users():
    users_info = [{'id': u.id, 'username': u.username} for u in User.query.all()]
    return jsonify({'users': users_info})


# --- API QUẢN LÝ FILE (ĐÃ SỬA ĐỔI) ---
@app.route('/files', methods=['GET'])
@login_required
def list_files():
    # SỬA ĐỔI: Lấy TẤT CẢ các file, không lọc theo người dùng
    files = File.query.all()
    return jsonify({'files': [file.filename for file in files]})

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    # Giữ nguyên logic upload
    if 'file' not in request.files: return jsonify({'message': 'Không tìm thấy file'}), 400
    file = request.files['file']
    if file.filename == '': return jsonify({'message': 'Chưa chọn file nào'}), 400
    filename = secure_filename(file.filename); file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    # Vẫn lưu lại thông tin người đã upload file
    new_file = File(filename=filename, owner=current_user); db.session.add(new_file); db.session.commit()
    return jsonify({'message': 'Tải file lên thành công!'}), 201

@app.route('/download/<filename>', methods=['GET'])
@login_required
def download_file(filename):
    # SỬA ĐỔI: Bỏ kiểm tra quyền sở hữu, chỉ cần file tồn tại là được tải
    file_record = File.query.filter_by(filename=filename).first()
    if not file_record: return jsonify({'message': 'File không tồn tại'}), 404
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/delete/<filename>', methods=['DELETE'])
@login_required
@admin_required # SỬA ĐỔI: Chỉ có ADMIN mới được phép xóa file
def delete_file(filename):
    file_record = File.query.filter_by(filename=filename).first()
    if not file_record: return jsonify({'message': 'File không tồn tại'}), 404
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename)); db.session.delete(file_record); db.session.commit()
        return jsonify({'message': f"File '{filename}' đã được xóa"})
    except Exception as e: db.session.rollback(); return jsonify({'message': f'Lỗi khi xóa file: {e}'}), 500

# ... (Các API admin và Socket.IO giữ nguyên) ...
@app.route('/admin/users', methods=['GET'])
@login_required
@admin_required
def get_all_users():
    users = User.query.all()
    user_list = [{'id': u.id, 'username': u.username, 'is_admin': u.is_admin} for u in users]
    return jsonify({'users': user_list})
# ... (Phần còn lại giữ nguyên như cũ) ...
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
