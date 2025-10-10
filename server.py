import eventlet
eventlet.monkey_patch()

import os, click, cloudinary, cloudinary.uploader, cloudinary.api
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_from_directory
from flask.cli import with_appcontext
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, or_, not_
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from functools import wraps
from flask_socketio import SocketIO, emit
import uuid
import logging
import urllib.parse
from dateutil import parser as dateparser # <-- THÊM THƯ VIỆN NÀY

# Cấu hình logging cơ bản
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- KHỞI TẠO VÀ CẤU HÌNH ---
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-fallback-secret-key-for-development')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Cấu hình Cloudinary
CLOUDINARY_ROOT_FOLDER = "pyside_chat_app"
CLOUDINARY_UPDATE_FOLDER = f"{CLOUDINARY_ROOT_FOLDER}/updates"
CLOUDINARY_AVATAR_FOLDER = f"{CLOUDINARY_ROOT_FOLDER}/avatars"
CLOUDINARY_USER_FILES_FOLDER = f"{CLOUDINARY_ROOT_FOLDER}/user_files"

db = SQLAlchemy(app)
login_manager = LoginManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# LƯU TRỮ NGƯỜI DÙNG ONLINE: {user_id: session_id}
online_users = {}

try:
    cloudinary.config(
        cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME'),
        api_key=os.environ.get('CLOUDINARY_API_KEY'),
        api_secret=os.environ.get('CLOUDINARY_API_SECRET')
    )
    if not os.environ.get('CLOUDINARY_CLOUD_NAME'):
        logger.warning("CLOUDINARY_CLOUD_NAME not set. File functionality may fail.")
except Exception as e:
    logger.error(f"Error configuring Cloudinary: {e}")

# --- DECORATOR, MODELS, USER_LOADER ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({'message': 'Yêu cầu quyền Admin!'}), 403
        return f(*args, **kwargs)
    return decorated_function
    
# Tạo hàm tiện ích để ghi log
def log_action(username, action, is_admin=False):
    log = Log(username=username, action=action, is_admin_action=is_admin)
    db.session.add(log)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to log action: {e}")


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    avatar_url = db.Column(db.String(256), nullable=True)

    files = db.relationship('File', backref='owner', lazy=True, cascade="all, delete-orphan")
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender_user', lazy=True, cascade="all, delete-orphan")
    received_messages = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient_user', lazy=True, cascade="all, delete-orphan")
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    public_id = db.Column(db.String(255), nullable=False, unique=True)
    resource_type = db.Column(db.String(50), nullable=False, default='raw')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    upload_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # --- THÊM HAI TRƯỜNG MỚI CHO LOG MỞ FILE ---
    last_opened_by = db.Column(db.String(80), nullable=True)
    last_opened_at = db.Column(db.DateTime, nullable=True)
    # ---------------------------------------------

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    
    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])

# --- MODEL MỚI CHO NHẬT KÝ ---
class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    username = db.Column(db.String(80), nullable=False) # Tên người dùng thực hiện hành động
    action = db.Column(db.String(512), nullable=False) # Chi tiết hành động
    is_admin_action = db.Column(db.Boolean, default=False) # Đánh dấu hành động Admin
# ------------------------------

class AppVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version_number = db.Column(db.String(50), nullable=False, unique=True)
    public_id = db.Column(db.String(255), nullable=False)
    download_url = db.Column(db.String(512), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def setup_app(app, db):
    """Hàm setup chạy một lần khi ứng dụng bắt đầu."""
    with app.app_context():
        try:
            db.create_all()
        except Exception as e:
            logger.error(f"FATAL ERROR: Could not create database tables: {e}")
        
        if User.query.first() is None:
            admin_user = os.environ.get('DEFAULT_ADMIN_USER', 'admin')
            admin_pass = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'adminpass')
            
            if admin_pass and User.query.filter_by(username=admin_user).first() is None:
                default_admin = User(username=admin_user, is_admin=True)
                default_admin.set_password(admin_pass)
                db.session.add(default_admin)
                db.session.commit()
                logger.info(f"Default admin user '{admin_user}' created.")
                log_action(admin_user, "Initial admin account created by system.", is_admin=True) # Ghi log

setup_app(app, db)

# --- CÁC ĐƯỜNG DẪN API (ROUTES) ---
@app.route('/update', methods=['GET'])
def check_for_update():
    # ... (giữ nguyên)
    pass
    # ...

@app.route('/admin/upload-update', methods=['POST'])
@admin_required
def upload_update():
    # ... (code tải file lên cloudinary)
    # ... (tạo new_version và commit)
    
    log_action(current_user.username, f"Uploaded and activated client update v{version_number}.", is_admin=True) # Ghi log
    
    return jsonify({'message': f'Bản cập nhật v{version_number} đã được tải lên và kích hoạt thành công!', 'url': download_url})

@app.route('/')
def index():
    logger.info("Health check received on /.")
    return "Backend server for the application is running!"

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username, password = data.get('username'), data.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            log_action(user.username, "Logged in successfully.") # Ghi log đăng nhập
            return jsonify({
                'message': 'Đăng nhập thành công!',
                'user_id': user.id,
                'username': user.username,
                'is_admin': user.is_admin,
                'avatar_url': user.avatar_url
            })
        log_action(username, "Failed login attempt.", is_admin=False) # Ghi log thất bại
        return jsonify({'message': 'Sai tên đăng nhập hoặc mật khẩu!'}), 401
    except Exception as e:
        logger.error(f"Error during login: {e}")
        return jsonify({'message': 'Lỗi server trong quá trình xử lý đăng nhập.'}), 500

# ... (các routes /online-users, /history giữ nguyên) ...

@app.route('/delete-file', methods=['POST'])
@login_required
def delete_file_post():
    data = request.get_json()
    public_id = data.get('public_id')
    
    if not public_id:
        return jsonify({'message': 'Thiếu ID công khai để xóa file.'}), 400
    
    file_record = File.query.filter_by(public_id=public_id).first()
    if not file_record:
        return jsonify({'message': 'File không tồn tại trong CSDL.'}), 404
    
    if not current_user.is_admin and file_record.user_id != current_user.id:
        return jsonify({'message': 'Bạn không có quyền xóa file này.'}), 403
    
    try:
        cloudinary.uploader.destroy(file_record.public_id, resource_type=file_record.resource_type)
        db.session.delete(file_record)
        db.session.commit()
        
        log_action(current_user.username, f"Deleted file: {file_record.filename} (ID: {file_record.public_id})", is_admin=current_user.is_admin) # Ghi log
        
        return jsonify({'message': 'File đã được xóa thành công.'})
    except Exception as e:
        logger.error(f"Error accessing /delete-file: {e}")
        return jsonify({'message': 'Lỗi khi xóa file: {}'.format(e)}), 500

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    # ... (code xử lý upload file lên cloudinary)
    # ... (tạo new_file và commit)
    
    log_action(current_user.username, f"Uploaded new file: {new_file.filename} (ID: {new_file.public_id})", is_admin=current_user.is_admin) # Ghi log
    
    return jsonify({'message': f'File {new_file.filename} đã được tải lên thành công!'})

@app.route('/files', methods=['GET'])
@login_required
def get_files():
    try:
        files_to_exclude = AppVersion.query.with_entities(AppVersion.public_id).all()
        files_to_exclude_list = [f[0] for f in files_to_exclude]
        
        files = File.query.filter(
            File.public_id.like(f'{CLOUDINARY_USER_FILES_FOLDER}/%'),
            not_(File.public_id.like(f'{CLOUDINARY_AVATAR_FOLDER}/%')),
            not_(File.public_id.in_(files_to_exclude_list))
        ).all()
        
        file_list = []
        for f in files:
            file_list.append({
                'filename': f.filename,
                'public_id': f.public_id,
                'uploaded_by': f.owner.username,
                # --- THÊM HAI TRƯỜNG MỚI ĐÃ CẬP NHẬT ---
                'last_opened_by': f.last_opened_by,
                'last_opened_at': f.last_opened_at.isoformat() if f.last_opened_at else None
                # ----------------------------------------
            })
            
        return jsonify({'files': file_list})
    except Exception as e:
        logger.error(f"Error accessing /files: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

# --- ROUTE MỚI: CẬP NHẬT THÔNG TIN MỞ FILE ---
@app.route('/file/opened/<path:public_id>', methods=['POST'])
@login_required
def record_file_opened(public_id):
    try:
        data = request.get_json()
        filename = data.get('filename', 'Unknown File')
        
        decoded_public_id = urllib.parse.unquote(public_id)

        file_record = File.query.filter_by(public_id=decoded_public_id).first()
        
        if not file_record:
            log_action(current_user.username, f"Failed to open file (ID not found): {filename}", is_admin=current_user.is_admin)
            return jsonify({'message': 'File không tồn tại.'}), 404

        # 1. Cập nhật thông tin file
        file_record.last_opened_by = current_user.username
        file_record.last_opened_at = datetime.now(timezone.utc)
        db.session.commit()
        
        # 2. Ghi nhật ký hoạt động
        log_action(current_user.username, f"Opened file: {file_record.filename}", is_admin=current_user.is_admin)
        
        return jsonify({'message': 'Đã ghi nhận sự kiện mở file.'})
    except Exception as e:
        logger.error(f"Error in /file/opened: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500
# ---------------------------------------------

# ... (các routes /download, /avatars, /avatar/upload, /avatar/select giữ nguyên) ...

@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_get_users():
    # ... (code load user list) ...
    pass

@app.route('/admin/users', methods=['POST'])
@admin_required
def admin_add_user():
    # ... (code tạo user) ...
    db.session.commit()
    
    # --- THÊM LOG ACTION ---
    log_action(current_user.username, f"Created new user: {username} (Admin: {is_admin})", is_admin=True)
    # -----------------------
    
    return jsonify({'message': f"Người dùng '{username}' đã được tạo."})

@app.route('/admin/users/<int:user_id>', methods=['PUT'])
@admin_required
def admin_edit_user(user_id):
    # ... (code sửa user) ...
    db.session.commit()
    
    # --- THÊM LOG ACTION ---
    log_action(current_user.username, f"Edited user ID {user_id} ({user.username}). Details: Pass Changed: {'Yes' if new_password else 'No'}, IsAdmin: {is_admin}", is_admin=True)
    # -----------------------
    
    return jsonify({'message': f"Thông tin người dùng ID {user_id} đã được cập nhật."})

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    # ... (code xóa user) ...
    db.session.commit()
    
    # --- THÊM LOG ACTION ---
    log_action(current_user.username, f"Deleted user ID {user_id}: {user.username}", is_admin=True)
    # -----------------------
    
    # ... (code xử lý socket.io và return)

# --- ROUTE MỚI: XEM NHẬT KÝ HOẠT ĐỘNG (CHỈ ADMIN) ---
@app.route('/admin/logs', methods=['GET'])
@admin_required
def admin_get_logs():
    try:
        # Lấy tối đa 500 log, sắp xếp theo thời gian mới nhất (desc)
        logs = Log.query.order_by(Log.timestamp.desc()).limit(500).all()
        
        log_list = []
        for log in logs:
            log_list.append({
                'timestamp': log.timestamp.isoformat(),
                'username': log.username,
                'action': log.action
            })
            
        # Đảo ngược danh sách để log mới nhất ở cuối
        return jsonify({'logs': log_list[::-1]})
    except Exception as e:
        logger.error(f"Error accessing /admin/logs GET: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500
# ----------------------------------------------------


# --- CÁC SỰ KIỆN SOCKET.IO ---
# ... (giữ nguyên các sự kiện Socket.IO) ...

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
