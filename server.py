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
import requests
import time
import urllib.parse 

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
CLOUDINARY_USER_FILES_FOLDER = f"{CLOUDINARY_ROOT_FOLDER}/user_files"

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
        return check_password_hash(password, self.password_hash)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    public_id = db.Column(db.String(255), nullable=False, unique=True)
    resource_type = db.Column(db.String(50), nullable=False, default='raw')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    upload_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_opened_by = db.Column(db.String(80), nullable=True)
    last_opened_at = db.Column(db.DateTime, nullable=True)
    
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

# TÁCH LOGIC KHỞI TẠO DATABASE RA KHỎI LUỒNG CHÍNH (Khắc phục Timeout)
def initialize_database(app, db):
    """Khởi tạo database và tạo admin user nếu cần."""
    with app.app_context():
        try:
            db.create_all() 
            logger.info("Database tables created successfully (or checked).")
        except Exception as e:
            logger.error(f"FATAL ERROR: Could not inspect or create database tables: {e}")
            
        if User.query.first() is None:
            admin_user = os.environ.get('DEFAULT_ADMIN_USER', 'admin')
            admin_pass = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'adminpass')
            
            if admin_pass and User.query.filter_by(username=admin_user).first() is None:
                default_admin = User(username=admin_user, is_admin=True)
                default_admin.set_password(admin_pass)
                db.session.add(default_admin)
                db.session.commit()
                logger.info(f"Default admin user '{admin_user}' created.")

# Gắn lệnh CLI để Render có thể chạy setup trước khi Gunicorn chạy chính
@app.cli.command("init-db")
@with_appcontext
def init_db_command():
    """Khởi tạo database và admin user cho Render Build Hook."""
    initialize_database(app, db)
    click.echo('Database initialized/checked.')

# ============================================================
# LOGIC KEEP ALIVE (Đã sửa lỗi context)
# ============================================================
SELF_PING_URL = os.environ.get('SELF_PING_URL')
keep_alive_started = False # Biến cờ

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

# Lệnh này không còn chạy ở cấp module nữa. Nó sẽ được gọi trong index().
# start_keep_alive_thread() 
# ============================================================

@app.route('/update', methods=['GET'])
def check_for_update():
    try:
        latest_version_record = AppVersion.query.order_by(AppVersion.timestamp.desc()).first()
        if latest_version_record:
            return jsonify({
                'latest_version': latest_version_record.version_number,
                'download_url': latest_version_record.download_url
            })
        return jsonify({'latest_version': "0.0.0", 'download_url': ""})
    except Exception as e:
        logger.error(f"Error accessing /update route: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/admin/upload-update', methods=['POST'])
@admin_required
def upload_update():
    if 'update_file' not in request.files:
        return jsonify({'message': 'Thiếu file cập nhật.'}), 400
    version_number = request.form.get('version_number')
    update_file = request.files['update_file']
    if not version_number:
        return jsonify({'message': 'Thiếu số phiên bản.'}), 400
    if AppVersion.query.filter_by(version_number=version_number).first():
        return jsonify({'message': f"Phiên bản {version_number} đã tồn tại."}), 400
    try:
        public_id = f"{CLOUDINARY_UPDATE_FOLDER}/client_{version_number}_{uuid.uuid4().hex[:6]}"
        upload_result = cloudinary.uploader.upload(update_file, public_id=public_id, folder=None, resource_type="auto")
        download_url, _ = cloudinary.utils.cloudinary_url(upload_result['public_id'], resource_type="raw", attachment=True, flags="download")
        new_version = AppVersion(version_number=version_number, public_id=upload_result['public_id'], download_url=download_url)
        db.session.add(new_version)
        db.session.commit()
        create_activity_log('UPLOAD_UPDATE', f'Phiên bản {version_number}')
        return jsonify({'message': f'Bản cập nhật v{version_number} đã được tải lên và kích hoạt thành công!', 'url': download_url})
    except Exception as e:
        logger.error(f"Error processing upload-update: {e}")
        return jsonify({'message': f'Lỗi khi tải file cập nhật lên: {e}'}), 500

@app.route('/')
def index():
    global keep_alive_started
    logger.info("Health check received on /.")
    
    # KHẮC PHỤC LỖI CONTEXT: Chỉ khởi động Keep-Alive khi ứng dụng đã load xong
    if not keep_alive_started:
        start_keep_alive_thread()
        keep_alive_started = True
        logger.info("Keep-Alive thread initialized successfully.")
        
    return "Backend server for the application is running!"

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username, password = data.get('username'), data.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            create_activity_log('LOGIN', f'Đăng nhập từ IP: {request.remote_addr}')
            return jsonify({'message': 'Đăng nhập thành công!', 'user_id': user.id, 'username': user.username, 'is_admin': user.is_admin, 'avatar_url': user.avatar_url})
        return jsonify({'message': 'Sai tên đăng nhập hoặc mật khẩu!'}), 401
    except Exception as e:
        logger.error(f"Error during login: {e}")
        return jsonify({'message': 'Lỗi server trong quá trình xử lý đăng nhập.'}), 500

@app.route('/online-users', methods=['GET'])
@login_required
def get_online_users():
    """Trả về danh sách người dùng đang online (không bao gồm bản thân)."""
    try:
        online_user_ids = list(online_users.keys())
        users = User.query.filter(User.id.in_(online_user_ids)).all()
        users_info = []
        for u in users:
            if u.id != current_user.id:
                users_info.append({'id': u.id, 'username': u.username, 'avatar_url': u.avatar_url})
        return jsonify({'users': users_info})
    except Exception as e:
        logger.error(f"Error accessing /online-users: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/all-users', methods=['GET'])
@login_required 
def get_all_users():
    """Trả về danh sách tất cả người dùng (online và offline) cho user đã đăng nhập."""
    try:
        users = User.query.all()
        users_info = []
        for u in users:
            if u.id != current_user.id:
                users_info.append({
                    'id': u.id, 
                    'username': u.username, 
                    'avatar_url': u.avatar_url,
                    'is_online': u.id in online_users
                })
        return jsonify({'users': users_info})
    except Exception as e:
        logger.error(f"Error accessing /all-users GET: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/history/<int:partner_id>', methods=['DELETE'])
@login_required
def delete_history(partner_id):
    try:
        partner = User.query.get(partner_id)
        if not partner:
            return jsonify({'message': 'User không tồn tại.'}), 404
        partner_username = partner.username
        db.session.query(Message).filter(or_((Message.sender_id == current_user.id) & (Message.recipient_id == partner_id), (Message.sender_id == partner_id) & (Message.recipient_id == current_user.id))).delete(synchronize_session='fetch')
        db.session.commit()
        create_activity_log('DELETE_CHAT_HISTORY', f'Với user: {partner_username}', target_user_id=partner_id)
        return jsonify({'message': f"Đã xóa lịch sử chat với user {partner_username}."})
    except Exception as e:
        logger.error(f"Error accessing /history DELETE: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/history/<int:partner_id>', methods=['GET'])
@login_required
def get_history(partner_id):
    try:
        messages_to_mark_read = db.session.query(Message).filter((Message.sender_id == partner_id) & (Message.recipient_id == current_user.id) & (Message.is_read == False))
        message_ids_to_update = [msg.id for msg in messages_to_mark_read.all()]
        
        messages_to_mark_read.update({Message.is_read: True})
        db.session.commit()
        
        last_sent_read = db.session.query(Message).filter((Message.sender_id == current_user.id) & (Message.recipient_id == partner_id) & (Message.is_read == True)).first()
        all_sent_is_read = True if last_sent_read else False
        
        all_messages = db.session.query(Message).filter(or_((Message.sender_id == current_user.id) & (Message.recipient_id == partner_id), (Message.sender_id == partner_id) & (Message.recipient_id == current_user.id))).order_by(Message.timestamp.asc()).all()
        
        history = []
        for msg in all_messages:
            is_mine = msg.sender_id == current_user.id
            msg_is_read = msg.is_read
            
            if is_mine:
                msg_is_read = all_sent_is_read
            
            history.append({'id': msg.id, 'sender': msg.sender.username, 'message': msg.content, 'is_read': msg_is_read})
        
        partner_sid = online_users.get(partner_id)
        if partner_sid and message_ids_to_update:
            emit('messages_seen', {'ids': message_ids_to_update}, room=partner_sid, namespace='/')
            
        return jsonify(history)
    except Exception as e:
        logger.error(f"Error accessing /history GET: {e}")
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
    
    target_folder_name = request.form.get('target_folder', 'Gốc')
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'Tên file không hợp lệ.'}), 400
        
    original_filename = file.filename
    try:
        file_base_name, file_extension = os.path.splitext(original_filename)
        safe_filename_part = secure_filename(file_base_name)
        
        folder_path = CLOUDINARY_USER_FILES_FOLDER
        if target_folder_name and target_folder_name != 'Gốc' and target_folder_name != 'Gốc (/)':
             clean_folder_name = target_folder_name.strip('/')
             folder_path = f"{CLOUDINARY_USER_FILES_FOLDER}/{clean_folder_name}"
        
        public_id_base = f"{folder_path}/{safe_filename_part}_{uuid.uuid4().hex[:6]}"
        
        upload_result = cloudinary.uploader.upload(file, public_id=public_id_base, resource_type="auto")
        resource_type_from_cloudinary = upload_result.get('resource_type', 'raw')
        
        new_file = File(filename=original_filename, public_id=upload_result['public_id'], resource_type=resource_type_from_cloudinary, user_id=current_user.id)
        db.session.add(new_file)
        db.session.commit()
        
        create_activity_log('UPLOAD_FILE', f'File: {original_filename} vào thư mục {target_folder_name}')
        
        return jsonify({'message': f'File {new_file.filename} đã được tải lên thành công vào thư mục {target_folder_name}!'})
    except Exception as e:
        logger.error(f"Error accessing /upload: {e}")
        return jsonify({'message': f'Lỗi khi tải file lên: {e}'}), 500

@app.route('/files', methods=['GET'])
@login_required
def get_files():
    try:
        search_term = request.args.get('search', '').strip()
        
        files_to_exclude = AppVersion.query.with_entities(AppVersion.public_id).all()
        files_to_exclude_list = [f[0] for f in files_to_exclude]
        
        files_query = File.query.filter(
            File.public_id.like(f'{CLOUDINARY_USER_FILES_FOLDER}/%'),
            not_(File.public_id.like(f'{CLOUDINARY_AVATAR_FOLDER}/%')),
            not_(File.public_id.in_(files_to_exclude_list))
        )
        
        if search_term:
            files_query = files_query.filter(File.filename.ilike(f'%{search_term}%'))

        files = files_query.all()
        
        file_list = []
        for f in files:
            uploaded_by_username = f.owner.username if f.owner else "Người dùng đã bị xóa"
            
            full_folder_prefix = f"{CLOUDINARY_USER_FILES_FOLDER}/"
            folder_name = 'Gốc'
            if full_folder_prefix in f.public_id:
                folder_path_raw = f.public_id.split(full_folder_prefix, 1)[-1]
                if '/' in folder_path_raw:
                    folder_name = folder_path_raw.rsplit('/', 1)[0]
                
            file_list.append({
                'filename': f.filename,
                'public_id': f.public_id,
                'uploaded_by': uploaded_by_username,
                'last_opened_by': f.last_opened_by,
                'last_opened_at': f.last_opened_at.isoformat() if f.last_opened_at else None,
                'folder': folder_name 
            })
        return jsonify({'files': file_list})
    except Exception as e:
        logger.error(f"Error accessing /files: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/download', methods=['POST'])
@login_required
def download_file():
    try:
        data = request.get_json()
        public_id = data.get('public_id')
        if not public_id:
            return jsonify({'message': 'Thiếu public_id'}), 400
        logger.info(f"[DOWNLOAD] Nhận yêu cầu tải file: {public_id}")
        file_record = File.query.filter_by(public_id=public_id).first()
        if not file_record:
            logger.warning(f"[DOWNLOAD] File không tồn tại trong DB: {public_id}")
            return jsonify({'message': 'File không tồn tại.'}), 404
        logger.info(f"[DOWNLOAD] Tìm thấy file: {file_record.filename}, resource_type: {file_record.resource_type}")
        download_url, _ = cloudinary.utils.cloudinary_url(file_record.public_id, resource_type=file_record.resource_type, type="upload", attachment=True, flags="attachment", secure=True)
        logger.info(f"[DOWNLOAD] URL tạo thành công")
        create_activity_log('DOWNLOAD_FILE', f'File: {file_record.filename}')
        return jsonify({'download_url': download_url})
    except Exception as e:
        logger.error(f"Error in /download: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/file/opened/<path:public_id>', methods=['POST'])
@login_required
def file_opened(public_id):
    try:
        file_record = File.query.filter_by(public_id=public_id).first()
        if not file_record:
            return jsonify({'message': 'File không tồn tại.'}), 404
        new_access_log = FileAccessLog(file_id=file_record.id, user_id=current_user.id)
        db.session.add(new_access_log)
        file_record.last_opened_by = current_user.username
        file_record.last_opened_at = datetime.now(timezone.utc)
        db.session.commit()
        create_activity_log('OPEN_FILE', f'File: {file_record.filename}')
        return jsonify({'message': 'Đã ghi nhận lần mở file.'})
    except Exception as e:
        logger.error(f"Error in /file/opened: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/file/update', methods=['POST'])
@login_required
def update_file_content():
    try:
        if 'file' not in request.files:
            return jsonify({'message': 'Thiếu file.'}), 400
        data = request.form
        public_id = data.get('public_id')
        if not public_id:
            return jsonify({'message': 'Thiếu public_id.'}), 400
        file_record = File.query.filter_by(public_id=public_id).first()
        if not file_record:
            return jsonify({'message': 'File không tồn tại trong hệ thống.'}), 404
        
        uploaded_file = request.files['file']
        logger.info(f"[AUTO-SYNC] User {current_user.username} đang cập nhật file: {file_record.filename}")
        upload_result = cloudinary.uploader.upload(uploaded_file, public_id=public_id, overwrite=True, resource_type=file_record.resource_type, invalidate=True)
        create_activity_log('UPDATE_FILE', f'Cập nhật file: {file_record.filename}')
        logger.info(f"[AUTO-SYNC] File {file_record.filename} đã được cập nhật thành công!")
        return jsonify({'message': f'File "{file_record.filename}" đã được cập nhật thành công!', 'version': upload_result.get('version'), 'updated_at': datetime.now(timezone.utc).isoformat()})
    except Exception as e:
        logger.error(f"Error in /file/update: {e}")
        return jsonify({'message': f'Lỗi khi cập nhật file: {str(e)}'}), 500

@app.route('/admin/logs/delete-all', methods=['DELETE'])
@admin_required
def admin_delete_all_logs():
    try:
        count = db.session.query(ActivityLog).delete()
        db.session.commit()
        create_activity_log('DELETE_ALL_LOGS', f'Đã xóa {count} bản ghi.')
        return jsonify({'message': f'Đã xóa {count} bản ghi nhật ký hệ thống.'}), 200
    except Exception as e:
        logger.error(f"Error deleting all logs: {e}")
        db.session.rollback()
        return jsonify({'message': 'Lỗi server khi xóa tất cả logs.'}), 500

@app.route('/admin/logs/delete/<int:log_id>', methods=['DELETE'])
@admin_required
def admin_delete_log(log_id):
    try:
        log_entry = ActivityLog.query.get(log_id)
        if not log_entry:
            return jsonify({'message': 'Log không tồn tại.'}), 404
        
        log_action = log_entry.action
        db.session.delete(log_entry)
        db.session.commit()
        create_activity_log('DELETE_SINGLE_LOG', f'Xóa log ID: {log_id}, Hành động: {log_action}')
        return jsonify({'message': f'Đã xóa bản ghi log ID {log_id}.'}), 200
    except Exception as e:
        logger.error(f"Error deleting single log: {e}")
        db.session.rollback()
        return jsonify({'message': 'Lỗi server khi xóa log đơn lẻ.'}), 500

def get_cloudinary_folder_path(folder_name):
    """Trả về đường dẫn Cloudinary đầy đủ hoặc thư mục gốc."""
    if folder_name == 'Gốc' or folder_name == 'Gốc (/)':
        return CLOUDINARY_USER_FILES_FOLDER
    clean_folder_name = folder_name.strip('/') 
    return f"{CLOUDINARY_USER_FILES_FOLDER}/{clean_folder_name}"

@app.route('/admin/folders', methods=['GET'])
@admin_required
def admin_get_folders():
    """Lấy danh sách thư mục con trong CLOUDINARY_USER_FILES_FOLDER."""
    try:
        folders_response = cloudinary.api.folders(CLOUDINARY_USER_FILES_FOLDER)
        
        folders = [f['name'] for f in folders_response.get('folders', [])]
        
        folders.insert(0, 'Gốc (/)') 
        
        return jsonify({'folders': folders})
    except Exception as e:
        logger.error(f"Error accessing /admin/folders GET: {e}")
        return jsonify({'folders': ['Gốc (/)']}), 200

@app.route('/admin/folders', methods=['POST'])
@admin_required
def admin_create_folder():
    data = request.get_json()
    folder_name = data.get('folder_name')
    if not folder_name or folder_name == 'Gốc (/)':
        return jsonify({'message': 'Thiếu tên thư mục hoặc tên không hợp lệ.'}), 400
    
    full_path = get_cloudinary_folder_path(folder_name)
    
    try:
        cloudinary.api.create_folder(full_path)
        create_activity_log('CREATE_FOLDER', f'Tạo thư mục: {folder_name}')
        return jsonify({'message': f"Đã tạo thư mục '{folder_name}' thành công!"}), 201
    except Exception as e:
        logger.error(f"Error creating folder: {e}")
        return jsonify({'message': f'Lỗi khi tạo thư mục: {e}'}), 500

@app.route('/admin/folders', methods=['PUT'])
@admin_required
def admin_rename_folder():
    data = request.get_json()
    old_name = data.get('old_name')
    new_name = data.get('new_name')
    if not old_name or not new_name or old_name == 'Gốc (/)':
        return jsonify({'message': 'Thiếu tên thư mục cũ/mới hoặc không thể đổi tên Gốc.'}), 400
        
    old_path = get_cloudinary_folder_path(old_name)
    new_path = get_cloudinary_folder_path(new_name)
    
    try:
        cloudinary.api.rename_folder(old_path, new_path)
        create_activity_log('RENAME_FOLDER', f'Đổi tên thư mục: {old_name} -> {new_name}')
        
        old_public_id_prefix = f"{old_path}/"
        new_public_id_prefix = f"{new_path}/"
        
        db.session.query(File).filter(File.public_id.like(f'{old_public_id_prefix}%')).update(
            {File.public_id: db.sql.func.replace(File.public_id, old_public_id_prefix, new_public_id_prefix)}, 
            synchronize_session=False
        )
        db.session.commit()
        
        return jsonify({'message': f"Đã đổi tên thư mục từ '{old_name}' thành '{new_name}' thành công!"}), 200
    except Exception as e:
        logger.error(f"Error renaming folder: {e}")
        return jsonify({'message': f'Lỗi khi đổi tên thư mục: {e}'}), 500
        
@app.route('/admin/folders', methods=['DELETE'])
@admin_required
def admin_delete_folder():
    data = request.get_json()
    folder_name = data.get('folder_name')
    if not folder_name or folder_name == 'Gốc (/)':
        return jsonify({'message': 'Tên thư mục không hợp lệ hoặc không thể xóa thư mục gốc.'}), 400

    full_path = get_cloudinary_folder_path(folder_name)
    
    try:
        search_result = cloudinary.api.resources(type="upload", prefix=f"{full_path}/", max_results=500)
        public_ids_to_delete = [res['public_id'] for res in search_result.get('resources', [])]
        
        if public_ids_to_delete:
            db.session.query(File).filter(File.public_id.in_(public_ids_to_delete)).delete(synchronize_session=False)
            db.session.commit()
            
            cloudinary.api.delete_resources(public_ids_to_delete)
        
        cloudinary.api.delete_folder(full_path, force_delete=True) 
        
        create_activity_log('DELETE_FOLDER', f'Xóa thư mục: {folder_name}')
        return jsonify({'message': f"Đã xóa thư mục '{folder_name}' và toàn bộ nội dung thành công!"}), 200
    except Exception as e:
        logger.error(f"Error deleting folder: {e}")
        db.session.rollback()
        return jsonify({'message': f'Lỗi khi xóa thư mục: {e}'}), 500


@app.route('/admin/logs', methods=['GET'])
@admin_required
def get_activity_logs():
    try:
        action_filter = request.args.get('action')
        logs_query = ActivityLog.query
        if action_filter and action_filter != "Tất cả":
            logs_query = logs_query.filter_by(action=action_filter)
        logs = logs_query.order_by(ActivityLog.timestamp.desc()).limit(100).all()
        logs_list = []
        for log in logs:
            user = User.query.get(log.user_id) if log.user_id else None
            target_user = User.query.get(log.target_user_id) if log.target_user_id else None
            logs_list.append({'id': log.id, 'username': user.username if user else 'System', 'action': log.action, 'details': log.details, 'target_username': target_user.username if target_user else None, 'timestamp': log.timestamp.isoformat()})
        return jsonify({'logs': logs_list})
    except Exception as e:
        logger.error(f"Error accessing /admin/logs: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/avatars', methods=['GET'])
@login_required
def get_user_avatars():
    try:
        user_files = File.query.filter(File.user_id == current_user.id, File.public_id.like(f'{CLOUDINARY_AVATAR_FOLDER}/%')).all()
        avatars = []
        for f in user_files:
            avatar_url, _ = cloudinary.utils.cloudinary_url(f.public_id, resource_type="image", width=100, height=100, crop="fill")
            avatars.append({'public_id': f.public_id, 'url': avatar_url})
        return jsonify({'avatars': avatars})
    except Exception as e:
        logger.error(f"Error accessing /avatars: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/avatar/upload', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        return jsonify({'message': 'Không tìm thấy file ảnh.'}), 400
    avatar = request.files['avatar']
    try:
        public_id = f"{CLOUDINARY_AVATAR_FOLDER}/user_{current_user.id}_{uuid.uuid4().hex[:6]}"
        upload_result = cloudinary.uploader.upload(avatar, public_id=public_id, folder=None, resource_type="image")
        
        new_file = File(filename=f"avatar_{uuid.uuid4().hex[:8]}", public_id=upload_result['public_id'], resource_type='image', user_id=current_user.id)
        db.session.add(new_file)
        current_user.avatar_url = upload_result['secure_url']
        
        db.session.commit()
        create_activity_log('UPLOAD_AVATAR', 'Tải lên avatar mới')
        return jsonify({'message': 'Avatar đã được cập nhật!', 'avatar_url': current_user.avatar_url})
    except Exception as e:
        logger.error(f"Error accessing /avatar/upload: {e}")
        return jsonify({'message': f'Lỗi khi tải lên avatar: {e}'}), 500

@app.route('/avatar/select', methods=['POST'])
@login_required
def select_avatar():
    data = request.get_json()
    public_id = data.get('public_id')
    if not public_id:
        return jsonify({'message': 'Thiếu ID công khai của avatar.'}), 400
    file_record = File.query.filter_by(public_id=public_id, user_id=current_user.id).first()
    if not file_record:
        return jsonify({'message': 'Avatar không hợp lệ hoặc không thuộc sở hữu của bạn.'}), 403
    try:
        new_avatar_url, _ = cloudinary.utils.cloudinary_url(file_record.public_id, resource_type="image", version=datetime.now().timestamp())
        current_user.avatar_url = new_avatar_url
        db.session.commit()
        create_activity_log('SELECT_AVATAR', 'Chọn avatar từ thư viện')
        return jsonify({'message': 'Avatar đã được cập nhật!', 'avatar_url': current_user.avatar_url})
    except Exception as e:
        logger.error(f"Error accessing /avatar/select: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_get_users():
    try:
        users = User.query.all()
        user_list = [{'id': u.id, 'username': u.username, 'is_admin': u.is_admin} for u in users]
        return jsonify({'users': user_list})
    except Exception as e:
        logger.error(f"Error accessing /admin/users GET: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/admin/users', methods=['POST'])
@admin_required
def admin_add_user():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        is_admin = data.get('is_admin', False)
        if not username or not password:
            return jsonify({'message': 'Thiếu tên đăng nhập hoặc mật khẩu.'}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({'message': 'Tên đăng nhập đã tồn tại.'}), 400
        new_user = User(username=username, is_admin=is_admin)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        create_activity_log('ADD_USER', f'Tạo user: {username}', target_user_id=new_user.id)
        return jsonify({'message': f"Người dùng '{username}' đã được tạo."})
    except Exception as e:
        logger.error(f"Error accessing /admin/users POST: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/admin/users/<int:user_id>', methods=['PUT'])
@admin_required
def admin_edit_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        changes = []
        new_username = data.get('username')
        if new_username and new_username != user.username:
            if User.query.filter_by(username=new_username).first():
                return jsonify({'message': 'Tên đăng nhập mới đã tồn tại.'}), 400
            changes.append(f'Username: {user.username} -> {new_username}')
            user.username = new_username
        new_password = data.get('password')
        if new_password:
            user.set_password(new_password)
            changes.append('Đổi mật khẩu')
        is_admin = data.get('is_admin')
        if is_admin is not None and is_admin != user.is_admin:
            changes.append(f'Admin: {user.is_admin} -> {is_admin}')
            user.is_admin = is_admin
        db.session.commit()
        if changes:
            create_activity_log('EDIT_USER', f'Sửa user ID {user_id}: {", ".join(changes)}', target_user_id=user_id)
        return jsonify({'message': f"Thông tin người dùng ID {user_id} đã được cập nhật."})
    except Exception as e:
        logger.error(f"Error accessing /admin/users PUT: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        if user.id == current_user.id:
            return jsonify({'message': 'Không thể tự xóa tài khoản của mình.'}), 400
        username = user.username
        
        cloudinary.api.delete_resources_by_prefix(f"{CLOUDINARY_AVATAR_FOLDER}/user_{user.id}_")
        
        db.session.delete(user)
        db.session.commit()
        
        if user_id in online_users:
            del online_users[user_id]
        
        create_activity_log('DELETE_USER', f'Xóa user: {username}', target_user_id=user_id)
        return jsonify({'message': f"Người dùng '{username}' đã bị xóa."})
    except Exception as e:
        logger.error(f"Error accessing /admin/users DELETE: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

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
    # Logic chạy Eventlet/SocketIO sử dụng cổng 5000 (Local)
    port = int(os.environ.get('PORT', 5000)) 
    
    initialize_database(app, db)
    
    # Chạy SocketIO trên cổng Render yêu cầu.
    socketio.run(app, host='0.0.0.0', port=port)
