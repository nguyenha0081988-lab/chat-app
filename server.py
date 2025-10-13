import eventlet
eventlet.monkey_patch()

import os, click, cloudinary, cloudinary.uploader, cloudinary.api
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_from_directory
from flask.cli import with_appcontext
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, or_, not_, and_
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from functools import wraps
from flask_socketio import SocketIO, emit
import uuid
import logging
import requests
import time
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-fallback-secret-key-for-development')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

CLOUDINARY_ROOT_FOLDER = "pyside_chat_app"
CLOUDINARY_UPDATE_FOLDER = f"{CLOUDINARY_ROOT_FOLDER}/updates"
CLOUDINARY_AVATAR_FOLDER = f"{CLOUDINARY_ROOT_FOLDER}/avatars"
# Đổi thư mục gốc chứa files user (mọi files user sẽ nằm trong subfolder của thư mục này)
CLOUDINARY_USER_FILES_ROOT = f"{CLOUDINARY_ROOT_FOLDER}/user_files" 
# Thư mục mặc định cho files user
DEFAULT_USER_FILES_FOLDER = f"{CLOUDINARY_USER_FILES_ROOT}/General"

db = SQLAlchemy(app)
login_manager = LoginManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

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

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({'message': 'Yêu cầu quyền Admin!'}), 403
        return f(*args, **kwargs)
    return decorated_function

def create_activity_log(action, details=None, target_user_id=None):
    """Ghi log hoạt động của user."""
    try:
        log_entry = ActivityLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action=action,
            details=details,
            target_user_id=target_user_id
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        logger.error(f"Error creating activity log: {e}")
        db.session.rollback()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    avatar_url = db.Column(db.String(256), nullable=True)

    files = db.relationship('File', backref='owner', lazy=True, cascade="all, delete-orphan")
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender_user', lazy=True, cascade="all, delete-orphan")
    received_messages = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient_user', lazy=True, cascade="all, delete-orphan")
    activity_logs = db.relationship('ActivityLog', foreign_keys='ActivityLog.user_id', backref='user', lazy=True, cascade="all, delete-orphan")
    file_accesses = db.relationship('FileAccessLog', backref='user', lazy=True, cascade="all, delete-orphan")
    
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
    last_opened_by = db.Column(db.String(80), nullable=True)
    last_opened_at = db.Column(db.DateTime, nullable=True)
    folder_path = db.Column(db.String(255), nullable=False, default=DEFAULT_USER_FILES_FOLDER)
    
    access_logs = db.relationship('FileAccessLog', backref='file', lazy=True, cascade="all, delete-orphan")

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    
    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])

class AppVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version_number = db.Column(db.String(50), nullable=False, unique=True)
    public_id = db.Column(db.String(255), nullable=False)
    download_url = db.Column(db.String(512), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=True)
    target_user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    target_user = db.relationship('User', foreign_keys=[target_user_id])

class FileAccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    opened_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def setup_app(app, db):
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database tables created successfully.")
            
            # Cập nhật các bản ghi file cũ nếu không có folder_path (cho khả năng migrate)
            File.query.filter(File.folder_path == None).update({'folder_path': DEFAULT_USER_FILES_FOLDER})
            db.session.commit()
            
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

setup_app(app, db)

# ============================================================
# LOGIC KEEP ALIVE
# ============================================================
SELF_PING_URL = os.environ.get('SELF_PING_URL')

def ping_self():
    """Thực hiện ping server định kỳ để ngăn Render ngủ đông."""
    PING_INTERVAL_SECONDS = 840 
    
    while True:
        eventlet.sleep(PING_INTERVAL_SECONDS)
        
        try:
            requests.get(SELF_PING_URL, timeout=10)
            logger.info(f"[KEEP-ALIVE] Ping thành công lúc: {datetime.now(timezone.utc)}")
        except Exception as e:
            logger.error(f"[KEEP-ALIVE ERROR]: Không thể ping URL {SELF_PING_URL}: {e}")

def start_keep_alive_thread():
    """Khởi tạo luồng ping nếu biến môi trường được đặt."""
    if SELF_PING_URL:
        logger.info(f"Bắt đầu luồng Keep-Alive cho URL: {SELF_PING_URL}")
        eventlet.spawn(ping_self) 

start_keep_alive_thread()
# ============================================================
# LOGIC QUẢN LÝ THƯ MỤC
# ============================================================

def _get_all_folders():
    """Lấy danh sách tất cả các thư mục con trong CLOUDINARY_USER_FILES_ROOT."""
    folders = {DEFAULT_USER_FILES_FOLDER}
    
    try:
        # Lấy tất cả các tiền tố (prefix) files từ Cloudinary API
        # Dùng `max_results=1` và `prefix` để scan thư mục gốc
        result = cloudinary.api.list_resources(
            type="upload", 
            prefix=CLOUDINARY_USER_FILES_ROOT,
            max_results=500
        )
        
        # Cloudinary API không trực tiếp liệt kê thư mục, ta phải suy luận từ public_id của files
        for res in result.get('resources', []):
            public_id = res['public_id']
            # Cắt public_id để lấy đường dẫn thư mục
            if '/' in public_id:
                folder_path = '/'.join(public_id.split('/')[:-1])
                folders.add(folder_path)
                
    except Exception as e:
        logger.error(f"Error fetching Cloudinary resources for folders: {e}")
        # Đảm bảo thư mục mặc định luôn được trả về
        return [DEFAULT_USER_FILES_FOLDER]

    # Sắp xếp và chỉ trả về các folder nằm trong thư mục gốc
    filtered_folders = sorted([
        f for f in folders if f.startswith(CLOUDINARY_USER_FILES_ROOT)
    ])
        
    return filtered_folders

def _is_valid_folder_name(name):
    """Kiểm tra tên thư mục hợp lệ (không chứa ký tự đặc biệt ngoài gạch ngang/dấu gạch dưới)."""
    return bool(name) and re.match(r'^[a-zA-Z0-9_\- ]+$', name)

def _get_safe_folder_path(folder_name):
    """Tạo đường dẫn Cloudinary an toàn từ tên thư mục."""
    safe_name = secure_filename(folder_name).replace('-', '_')
    return f"{CLOUDINARY_USER_FILES_ROOT}/{safe_name}"

@app.route('/admin/folders', methods=['GET'])
@login_required
def get_folders():
    """Trả về danh sách tất cả các thư mục files hiện có. Admin thấy tất cả, User thường thấy mặc định."""
    if not current_user.is_admin:
        # User thường chỉ cần biết thư mục mặc định
        return jsonify({'folders': [DEFAULT_USER_FILES_FOLDER]}), 200 
        
    folders = _get_all_folders()
    return jsonify({'folders': folders})

@app.route('/admin/folders', methods=['POST'])
@admin_required
def create_folder():
    """Tạo thư mục mới."""
    data = request.get_json()
    folder_name = data.get('folder_name')
    if not _is_valid_folder_name(folder_name):
        return jsonify({'message': 'Tên thư mục không hợp lệ. Chỉ cho phép chữ, số, gạch ngang, gạch dưới và khoảng trắng.'}), 400
    
    new_folder_path = _get_safe_folder_path(folder_name)
    
    # Kiểm tra xem thư mục đã tồn tại (dựa trên convention đặt tên)
    if new_folder_path in _get_all_folders():
        return jsonify({'message': f'Thư mục "{folder_name}" đã tồn tại.'}), 400

    # Kỹ thuật tạo folder trên Cloudinary: Tải lên một file dummy (placeholder)
    dummy_file_path = "data:image/gif;base64,R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw=="
    dummy_public_id = f"{new_folder_path}/.placeholder_{uuid.uuid4().hex[:4]}"
    
    try:
        cloudinary.uploader.upload(dummy_file_path, public_id=dummy_public_id, resource_type="image")
        
        # Xóa file dummy ngay sau khi folder được tạo
        cloudinary.uploader.destroy(dummy_public_id, resource_type='image') 
        
        create_activity_log('CREATE_FOLDER', f'Tạo thư mục: {folder_name}')
        
        return jsonify({'message': f'Thư mục "{folder_name}" đã được tạo thành công!', 'folder_path': new_folder_path}), 200
        
    except Exception as e:
        logger.error(f"Error creating folder: {e}")
        return jsonify({'message': f'Lỗi khi tạo thư mục: {e}'}), 500

@app.route('/admin/folders', methods=['DELETE'])
@admin_required
def delete_folder():
    """Xóa thư mục (và tất cả files bên trong)"""
    data = request.get_json()
    folder_path = data.get('folder_path')
    
    if not folder_path or not folder_path.startswith(CLOUDINARY_USER_FILES_ROOT):
        return jsonify({'message': 'Đường dẫn thư mục không hợp lệ.'}), 400
    if folder_path == CLOUDINARY_USER_FILES_ROOT or folder_path == DEFAULT_USER_FILES_FOLDER:
        return jsonify({'message': 'Không thể xóa thư mục gốc hoặc thư mục mặc định "General".'}), 400
        
    try:
        # Xóa tất cả tài nguyên trong thư mục trên Cloudinary
        deletion_result = cloudinary.api.delete_resources_by_prefix(folder_path, resource_type="all")
        
        # Xóa tất cả các bản ghi file liên quan trong DB
        count = File.query.filter(File.folder_path == folder_path).delete(synchronize_session='fetch')
        db.session.commit()
        
        create_activity_log('DELETE_FOLDER', f'Xóa thư mục: {folder_path.split("/")[-1]} và {count} files')
        
        return jsonify({'message': f'Đã xóa thư mục "{folder_path.split("/")[-1]}" và {count} files thành công.'}), 200
        
    except Exception as e:
        logger.error(f"Error deleting folder {folder_path}: {e}")
        db.session.rollback()
        return jsonify({'message': f'Lỗi khi xóa thư mục: {e}'}), 500

@app.route('/admin/folders', methods=['PUT'])
@admin_required
def rename_folder():
    """Đổi tên thư mục (di chuyển files trên Cloudinary và cập nhật DB)."""
    data = request.get_json()
    old_path = data.get('old_path')
    new_name = data.get('new_name')
    
    if not old_path or not new_name or not old_path.startswith(CLOUDINARY_USER_FILES_ROOT):
        return jsonify({'message': 'Đường dẫn cũ hoặc tên mới không hợp lệ.'}), 400
    if old_path == DEFAULT_USER_FILES_FOLDER:
        return jsonify({'message': 'Không thể đổi tên thư mục mặc định "General".'}), 400
    if not _is_valid_folder_name(new_name):
        return jsonify({'message': 'Tên thư mục mới không hợp lệ.'}), 400
        
    new_path = _get_safe_folder_path(new_name)
    if new_path == old_path:
        return jsonify({'message': 'Tên thư mục không thay đổi.'}), 400
        
    # Kiểm tra xem tên mới có bị trùng với thư mục đã tồn tại không
    if new_path in _get_all_folders():
        return jsonify({'message': 'Thư mục có tên mới này đã tồn tại.'}), 400

    files_to_update = File.query.filter(File.folder_path == old_path).all()
    count = len(files_to_update)
        
    try:
        # TỰ ĐỘNG ĐỔI TÊN/DI CHUYỂN FILES TRÊN CLOUDINARY
        for file in files_to_update:
            file_name_part = file.public_id.split('/')[-1]
            new_public_id = f"{new_path}/{file_name_part}"
            
            # Đổi tên trên Cloudinary
            cloudinary.uploader.rename(
                file.public_id, 
                new_public_id, 
                overwrite=True, 
                resource_type=file.resource_type
            )
            
            # Cập nhật DB
            file.public_id = new_public_id
            file.folder_path = new_path
        
        db.session.commit()
        
        create_activity_log('RENAME_FOLDER', f'Đổi tên thư mục: {old_path.split("/")[-1]} -> {new_name} ({count} files)')
        
        return jsonify({'message': f'Đã đổi tên thư mục thành "{new_name}" và cập nhật {count} files thành công.'}), 200
        
    except Exception as e:
        logger.error(f"Error renaming folder: {e}")
        db.session.rollback()
        return jsonify({'message': f'Lỗi khi đổi tên thư mục: {e}'}), 500


# ... (Giữ nguyên các API còn lại: /update, /, /login, /online-users, /all-users)
# ... (Giữ nguyên các API chat: /history)


@app.route('/files', methods=['GET'])
@login_required
def get_files():
    """Trả về danh sách files, hỗ trợ lọc theo thư mục và tìm kiếm theo tên."""
    try:
        folder_filter = request.args.get('folder', CLOUDINARY_USER_FILES_ROOT)
        search_term = request.args.get('search_term')
        
        files_to_exclude = AppVersion.query.with_entities(AppVersion.public_id).all()
        files_to_exclude_list = [f[0] for f in files_to_exclude]
        
        query_filters = [
            not_(File.public_id.like(f'{CLOUDINARY_AVATAR_FOLDER}/%')),
            not_(File.public_id.in_(files_to_exclude_list))
        ]
        
        # 1. Lọc theo thư mục
        if folder_filter and folder_filter != CLOUDINARY_USER_FILES_ROOT:
            query_filters.append(File.folder_path == folder_filter)
        elif folder_filter == CLOUDINARY_USER_FILES_ROOT:
             query_filters.append(File.folder_path.like(f'{CLOUDINARY_USER_FILES_ROOT}/%'))
        else:
            query_filters.append(File.folder_path.like(f'{CLOUDINARY_USER_FILES_ROOT}/%'))

        # 2. Tìm kiếm theo tên file (case-insensitive)
        if search_term:
            query_filters.append(File.filename.ilike(f'%{search_term}%'))

        files = File.query.filter(and_(*query_filters)).all()
        
        file_list = []
        for f in files:
            uploaded_by_username = f.owner.username if f.owner else "Người dùng đã bị xóa"

            file_list.append({
                'filename': f.filename,
                'public_id': f.public_id,
                'uploaded_by': uploaded_by_username,
                'last_opened_by': f.last_opened_by,
                'last_opened_at': f.last_opened_at.isoformat() if f.last_opened_at else None,
                'folder_path': f.folder_path
            })
        return jsonify({'files': file_list})
    except Exception as e:
        logger.error(f"Error accessing /files: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

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
    if not current_user.is_admin:
        return jsonify({'message': 'Bạn không có quyền xóa file này.'}), 403
    try:
        cloudinary.uploader.destroy(file_record.public_id, resource_type=file_record.resource_type)
        create_activity_log('DELETE_FILE', f'File: {file_record.filename}')
        db.session.delete(file_record)
        db.session.commit()
        return jsonify({'message': 'File đã được xóa thành công.'})
    except Exception as e:
        logger.error(f"Error accessing /delete-file: {e}")
        return jsonify({'message': f'Lỗi khi xóa file: {e}'}), 500

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'Không tìm thấy file.'}), 400
    
    file = request.files['file']
    # LẤY THƯ MỤC TỪ FORM DATA
    folder_path = request.form.get('folder_path', DEFAULT_USER_FILES_FOLDER) 
    
    if file.filename == '':
        return jsonify({'message': 'Tên file không hợp lệ.'}), 400
    
    # Kiểm tra tính hợp lệ và Fallback an toàn
    if not folder_path.startswith(CLOUDINARY_USER_FILES_ROOT):
         folder_path = DEFAULT_USER_FILES_FOLDER
         
    original_filename = file.filename
    
    try:
        file_base_name, file_extension = os.path.splitext(original_filename)
        safe_filename_part = secure_filename(file_base_name)
        
        # Xây dựng public_id với folder_path đầy đủ
        public_id_part = f"{safe_filename_part}_{uuid.uuid4().hex[:6]}{file_extension}"
        public_id_base = f"{folder_path}/{public_id_part}" 
        
        upload_result = cloudinary.uploader.upload(file, public_id=public_id_base, resource_type="auto")
        resource_type_from_cloudinary = upload_result.get('resource_type', 'raw')
        
        new_file = File(
            filename=original_filename, 
            public_id=upload_result['public_id'], 
            resource_type=resource_type_from_cloudinary, 
            user_id=current_user.id,
            folder_path=folder_path # LƯU TRƯỜNG THƯ MỤC
        )
        db.session.add(new_file)
        db.session.commit()
        create_activity_log('UPLOAD_FILE', f'File: {original_filename} vào folder: {folder_path.split("/")[-1]}')
        
        return jsonify({'message': f'File {new_file.filename} đã được tải lên thành công vào {folder_path.split("/")[-1]}!'})
        
    except Exception as e:
        logger.error(f"Error accessing /upload: {e}")
        return jsonify({'message': f'Lỗi khi tải file lên: {e}'}), 500

# ... (Giữ nguyên các API còn lại: /download, /file/opened, /file/update, /admin/logs, /avatars, /admin/users)

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        user_id = current_user.id
        user_data = {'id': user_id, 'username': current_user.username, 'avatar_url': current_user.avatar_url}
        online_users[user_id] = request.sid
        logger.info(f"User {current_user.username} connected (SID: {request.sid})")
        emit('user_connected', user_data, broadcast=True, include_self=False)
        unread_messages = (db.session.query(Message.sender_id).filter(Message.recipient_id == current_user.id, Message.is_read == False).group_by(Message.sender_id).all())
        counts_dict = {}
        for sender_id, in unread_messages:
            sender = User.query.get(sender_id)
            if sender:
                count = Message.query.filter_by(sender_id=sender_id, recipient_id=current_user.id, is_read=False).count()
                counts_dict[sender.username] = count
        if counts_dict:
            emit('offline_notifications', {'counts': counts_dict}, room=request.sid)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        user_id = current_user.id
        username = current_user.username
        if user_id in online_users:
            del online_users[user_id]
            logger.info(f"User {username} disconnected")
            emit('user_disconnected', {'id': user_id, 'username': username}, broadcast=True, include_self=False)
        create_activity_log('LOGOUT', 'Ngắt kết nối')

@socketio.on('private_message')
@login_required
def handle_private_message(data):
    recipient_id = data.get('recipient_id')
    content = data.get('message')
    if not recipient_id or not content:
        return
    new_msg = Message(sender_id=current_user.id, recipient_id=recipient_id, content=content)
    db.session.add(new_msg)
    db.session.commit()
    recipient = User.query.get(recipient_id)
    if recipient:
        create_activity_log('SEND_MESSAGE', f'Gửi tin nhắn đến: {recipient.username}', target_user_id=recipient_id)
    msg_data = {'id': new_msg.id, 'sender': current_user.username, 'message': content, 'is_read': False}
    recipient_sid = online_users.get(recipient_id)
    if recipient_sid:
        emit('message_from_server', msg_data, room=recipient_sid)
    emit('message_from_server', msg_data, room=request.sid)

@socketio.on('start_typing')
@login_required
def handle_start_typing(data):
    recipient_sid = online_users.get(data.get('recipient_id'))
    if recipient_sid:
        emit('user_is_typing', {'username': current_user.username}, room=recipient_sid)

@socketio.on('stop_typing')
@login_required
def handle_stop_typing(data):
    recipient_sid = online_users.get(data.get('recipient_id'))
    if recipient_sid:
        emit('user_stopped_typing', {'username': current_user.username}, room=recipient_sid)

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
