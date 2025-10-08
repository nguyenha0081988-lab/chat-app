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

# --- KHỞI TẠO VÀ CẤU HÌNH ---
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-fallback-secret-key-for-development')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Cấu hình Cloudinary (Yêu cầu biến môi trường CLOUDINARY_*)
CLOUDINARY_FOLDER = "pyside_chat_app"
CLOUDINARY_UPDATE_FOLDER = f"{CLOUDINARY_FOLDER}/updates" # Thư mục riêng cho file update
CLOUDINARY_AVATAR_FOLDER = f"{CLOUDINARY_FOLDER}/avatars" # Thư mục lưu trữ các avatar cũ

db = SQLAlchemy(app)
login_manager = LoginManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

online_users = {}

cloudinary.config(
    cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME'), 
    api_key=os.environ.get('CLOUDINARY_API_KEY'), 
    api_secret=os.environ.get('CLOUDINARY_API_SECRET')
)

# --- DECORATOR, MODELS, USER_LOADER ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin: 
            return jsonify({'message': 'Yêu cầu quyền Admin!'}), 403
        return f(*args, **kwargs)
    return decorated_function

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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)

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
    """Lưu trữ thông tin về các bản cập nhật của ứng dụng."""
    id = db.Column(db.Integer, primary_key=True)
    version_number = db.Column(db.String(50), nullable=False, unique=True)
    public_id = db.Column(db.String(255), nullable=False)
    download_url = db.Column(db.String(512), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id): 
    return User.query.get(int(user_id))

@app.before_request
def create_tables_and_admin():
    with app.app_context():
        if not inspect(db.engine).has_table('user'):
             db.create_all()
             
        if User.query.first() is None:
            admin_user = os.environ.get('DEFAULT_ADMIN_USER', 'admin')
            admin_pass = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'adminpass')
            
            if admin_pass and User.query.filter_by(username=admin_user).first() is None:
                default_admin = User(username=admin_user, is_admin=True)
                default_admin.set_password(admin_pass)
                db.session.add(default_admin)
                db.session.commit()
                print(f"Default admin user '{admin_user}' created.")

# --- CÁC ĐƯỜNG DẪN API (ROUTES) ---
@app.route('/update', methods=['GET'])
def check_for_update():
    """Cung cấp phiên bản mới nhất và link tải xuống."""
    latest_version_record = AppVersion.query.order_by(AppVersion.timestamp.desc()).first()
    
    if latest_version_record:
        return jsonify({
            'latest_version': latest_version_record.version_number,
            'download_url': latest_version_record.download_url
        })
    
    return jsonify({
        'latest_version': "0.0.0",
        'download_url': ""
    })

@app.route('/admin/upload-update', methods=['POST'])
@admin_required
def upload_update():
    """Upload file cập nhật client (dành cho Admin)."""
    if 'update_file' not in request.files:
        return jsonify({'message': 'Thiếu file cập nhật.'}), 400
        
    version_number = request.form.get('version_number')
    update_file = request.files['update_file']

    if not version_number:
        return jsonify({'message': 'Thiếu số phiên bản.'}), 400
    if AppVersion.query.filter_by(version_number=version_number).first():
        return jsonify({'message': f"Phiên bản {version_number} đã tồn tại."}), 400

    try:
        # Tải lên Cloudinary vào thư mục CLOUDINARY_UPDATE_FOLDER
        public_id = f"{CLOUDINARY_UPDATE_FOLDER}/client_{version_number}_{uuid.uuid4().hex[:6]}"
        upload_result = cloudinary.uploader.upload(
            update_file, 
            public_id=public_id,
            folder=CLOUDINARY_UPDATE_FOLDER,
            resource_type="auto"
        )
        
        # Tạo URL tải xuống
        download_url, _ = cloudinary.utils.cloudinary_url(
            upload_result['public_id'], 
            resource_type="raw", 
            attachment=True, 
            flags="download"
        )

        # Lưu vào DB
        new_version = AppVersion(
            version_number=version_number,
            public_id=upload_result['public_id'],
            download_url=download_url
        )
        db.session.add(new_version)
        db.session.commit()
        
        return jsonify({'message': f'Bản cập nhật v{version_number} đã được tải lên và kích hoạt thành công!', 'url': download_url})
    except Exception as e:
        print(f"Cloudinary upload error: {e}")
        return jsonify({'message': f'Lỗi khi tải file cập nhật lên: {e}'}), 500

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

@app.route('/online-users', methods=['GET'])
@login_required
def get_online_users():
    users_info = [{'id': u.id, 'username': u.username, 'avatar_url': u.avatar_url} for u in User.query.all()]
    return jsonify({'users': users_info})

@app.route('/history/<int:partner_id>', methods=['DELETE'])
@login_required
def delete_history(partner_id):
    partner = User.query.get(partner_id)
    if not partner: return jsonify({'message': 'User không tồn tại.'}), 404
    partner_username = partner.username
    db.session.query(Message).filter(or_((Message.sender_id == current_user.id) & (Message.recipient_id == partner_id), (Message.sender_id == partner_id) & (Message.recipient_id == current_user.id))).delete(synchronize_session='fetch')
    db.session.commit()
    return jsonify({'message': f"Đã xóa lịch sử chat với user {partner_username}."})

@app.route('/history/<int:partner_id>', methods=['GET'])
@login_required
def get_history(partner_id):
    messages_to_mark_read = db.session.query(Message).filter((Message.sender_id == partner_id) & (Message.recipient_id == current_user.id) & (Message.is_read == False))
    message_ids_to_update = [msg.id for msg in messages_to_mark_read.all()]
    messages_to_mark_read.update({Message.is_read: True}); db.session.commit()
    all_messages = db.session.query(Message).filter(or_((Message.sender_id == current_user.id) & (Message.recipient_id == partner_id), (Message.sender_id == partner_id) & (Message.recipient_id == current_user.id))).order_by(Message.timestamp.asc()).all()
    history = [{'id': msg.id, 'sender': msg.sender.username, 'message': msg.content, 'is_read': msg.is_read} for msg in all_messages]
    partner_sid = online_users.get(partner_id)
    if partner_sid and message_ids_to_update: emit('messages_seen', {'ids': message_ids_to_update}, room=partner_sid, namespace='/')
    return jsonify(history)

@app.route('/delete-file', methods=['POST'])
@login_required
def delete_file_post():
    data = request.get_json(); public_id = data.get('public_id')
    if not public_id: return jsonify({'message': 'Thiếu ID công khai để xóa file.'}), 400
    file_record = File.query.filter_by(public_id=public_id).first()
    if not file_record: return jsonify({'message': 'File không tồn tại trong CSDL.'}), 404
    if not current_user.is_admin and file_record.user_id != current_user.id: return jsonify({'message': 'Bạn không có quyền xóa file này.'}), 403
    try:
        cloudinary.uploader.destroy(file_record.public_id, resource_type="raw")
        db.session.delete(file_record); db.session.commit()
        return jsonify({'message': 'File đã được xóa thành công.'})
    except Exception as e: return jsonify({'message': f'Lỗi khi xóa file: {e}'}), 500

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files: return jsonify({'message': 'Không tìm thấy file.'}), 400
    file = request.files['file']
    if file.filename == '': return jsonify({'message': 'Tên file không hợp lệ.'}), 400
    try:
        # Tải lên Cloudinary vào thư mục chung, không phải update hay avatar
        public_id = f"{CLOUDINARY_FOLDER}/user_files/{uuid.uuid4().hex}"
        upload_result = cloudinary.uploader.upload(file, public_id=public_id, folder=f"{CLOUDINARY_FOLDER}/user_files", resource_type="auto")
        new_file = File(filename=secure_filename(file.filename), public_id=upload_result['public_id'], user_id=current_user.id)
        db.session.add(new_file); db.session.commit()
        return jsonify({'message': f'File {new_file.filename} đã được tải lên thành công!'})
    except Exception as e: return jsonify({'message': f'Lỗi khi tải file lên: {e}'}), 500

@app.route('/files', methods=['GET'])
@login_required
def get_files():
    """Chỉ trả về các file KHÔNG phải avatar hay bản cập nhật."""
    
    # Lọc tất cả các file có public_id không chứa đường dẫn của avatar và update
    # Note: Đây là cách lọc dựa trên quy ước đặt tên public_id của Cloudinary
    
    avatar_prefix = f"{CLOUDINARY_AVATAR_FOLDER}/"
    update_prefix = f"{CLOUDINARY_UPDATE_FOLDER}/"

    files_to_exclude = AppVersion.query.with_entities(AppVersion.public_id).all()
    files_to_exclude_list = [f[0] for f in files_to_exclude]
    
    # Lọc các file KHÔNG phải avatar (dựa trên tiền tố) VÀ KHÔNG phải file cập nhật
    files = File.query.filter(
        (File.user_id == current_user.id),
        not_(File.public_id.like(f'{CLOUDINARY_AVATAR_FOLDER}/%')), # Loại trừ tất cả avatar
        not_(File.public_id.in_(files_to_exclude_list)) # Loại trừ file update (đảm bảo an toàn)
    ).all()
    
    file_list = [{'filename': f.filename, 'public_id': f.public_id} for f in files]
    return jsonify({'files': file_list})

@app.route('/download/<string:public_id>', methods=['GET'])
@login_required
def download_file(public_id):
    file_record = File.query.filter_by(public_id=public_id).first()
    if not file_record: return jsonify({'message': 'File không tồn tại.'}), 404
    download_url, _ = cloudinary.utils.cloudinary_url(file_record.public_id, resource_type="raw", attachment=True, flags="download")
    return jsonify({'download_url': download_url})

@app.route('/avatars', methods=['GET'])
@login_required
def get_user_avatars():
    # File avatar được lưu trong File table
    user_files = File.query.filter(File.user_id == current_user.id, File.public_id.like(f'{CLOUDINARY_AVATAR_FOLDER}/%')).all(); avatars = []
    for f in user_files:
        avatar_url, _ = cloudinary.utils.cloudinary_url(f.public_id, resource_type="image", width=100, height=100, crop="fill")
        avatars.append({'public_id': f.public_id, 'url': avatar_url})
    return jsonify({'avatars': avatars})

@app.route('/avatar/upload', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files: return jsonify({'message': 'Không tìm thấy file ảnh.'}), 400
    avatar = request.files['avatar']
    
    try:
        # Tải lên Cloudinary vào thư mục CLOUDINARY_AVATAR_FOLDER
        public_id = f"{CLOUDINARY_AVATAR_FOLDER}/user_{current_user.id}_{uuid.uuid4().hex[:6]}"
        upload_result = cloudinary.uploader.upload(
            avatar, 
            public_id=public_id,
            folder=CLOUDINARY_AVATAR_FOLDER,
            resource_type="image"
        )
        
        # Lưu bản ghi avatar vào Files
        new_file = File(
            filename=f"avatar_{uuid.uuid4().hex[:8]}", 
            public_id=upload_result['public_id'],
            user_id=current_user.id
        )
        db.session.add(new_file)
        
        # Cập nhật avatar_url chính của user
        current_user.avatar_url = upload_result['secure_url']
        db.session.commit()
        
        return jsonify({'message': 'Avatar đã được cập nhật!', 'avatar_url': current_user.avatar_url})
    except Exception as e: return jsonify({'message': f'Lỗi khi tải lên avatar: {e}'}), 500

@app.route('/avatar/select', methods=['POST'])
@login_required
def select_avatar():
    data = request.get_json(); public_id = data.get('public_id')
    if not public_id: return jsonify({'message': 'Thiếu ID công khai của avatar.'}), 400
    file_record = File.query.filter_by(public_id=public_id, user_id=current_user.id).first()
    if not file_record: return jsonify({'message': 'Avatar không hợp lệ hoặc không thuộc sở hữu của bạn.'}), 403
    try:
        new_avatar_url, _ = cloudinary.utils.cloudinary_url(file_record.public_id, resource_type="image", version=datetime.now().timestamp())
        current_user.avatar_url = new_avatar_url; db.session.commit()
        return jsonify({'message': 'Avatar đã được cập nhật!', 'avatar_url': current_user.avatar_url})
    except Exception as e: return jsonify({'message': f'Lỗi khi chọn avatar: {e}'}), 500

@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_get_users():
    users = User.query.all(); user_list = [{'id': u.id, 'username': u.username, 'is_admin': u.is_admin} for u in users]
    return jsonify({'users': user_list})

@app.route('/admin/users', methods=['POST'])
@admin_required
def admin_add_user():
    data = request.get_json(); username = data.get('username'); password = data.get('password'); is_admin = data.get('is_admin', False)
    if not username or not password: return jsonify({'message': 'Thiếu tên đăng nhập hoặc mật khẩu.'}), 400
    if User.query.filter_by(username=username).first(): return jsonify({'message': 'Tên đăng nhập đã tồn tại.'}), 400
    new_user = User(username=username, is_admin=is_admin); new_user.set_password(password); db.session.add(new_user); db.session.commit()
    return jsonify({'message': f"Người dùng '{username}' đã được tạo."})

@app.route('/admin/users/<int:user_id>', methods=['PUT'])
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id); data = request.get_json()
    new_username = data.get('username')
    if new_username and new_username != user.username:
        if User.query.filter_by(username=new_username).first(): return jsonify({'message': 'Tên đăng nhập mới đã tồn tại.'}), 400
        user.username = new_username
    new_password = data.get('password')
    if new_password: user.set_password(new_password)
    is_admin = data.get('is_admin')
    if is_admin is not None: user.is_admin = is_admin
    db.session.commit(); return jsonify({'message': f"Thông tin người dùng ID {user_id} đã được cập nhật."})

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id: return jsonify({'message': 'Không thể tự xóa tài khoản của mình.'}), 400
    if user.avatar_url: cloudinary.uploader.destroy(f"{CLOUDINARY_FOLDER}/avatar/{user.id}", resource_type="image")
    db.session.delete(user); db.session.commit()
    if user_id in online_users: del online_users[user_id]
    return jsonify({'message': f"Người dùng '{user.username}' đã bị xóa."})

# --- CÁC SỰ KIỆN SOCKET.IO ---
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        online_users[current_user.id] = request.sid; print(f"User {current_user.username} connected (SID: {request.sid})")
        unread_messages = (db.session.query(Message.sender_id).filter(Message.recipient_id == current_user.id, Message.is_read == False).group_by(Message.sender_id).all())
        counts_dict = {}
        for sender_id, in unread_messages:
            sender = User.query.get(sender_id)
            if sender:
                count = Message.query.filter_by(sender_id=sender_id, recipient_id=current_user.id, is_read=False).count()
                counts_dict[sender.username] = count
        if counts_dict: emit('offline_notifications', {'counts': counts_dict}, room=request.sid)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        if current_user.id in online_users: del online_users[current_user.id]; print(f"User {current_user.username} disconnected")

@socketio.on('private_message')
@login_required
def handle_private_message(data):
    recipient_id = data.get('recipient_id'); content = data.get('message')
    if not recipient_id or not content: return 
    new_msg = Message(sender_id=current_user.id, recipient_id=recipient_id, content=content); db.session.add(new_msg); db.session.commit()
    msg_data = {'id': new_msg.id, 'sender': current_user.username, 'message': content, 'is_read': False }
    recipient_sid = online_users.get(recipient_id)
    if recipient_sid: emit('message_from_server', msg_data, room=recipient_sid)
    emit('message_from_server', msg_data, room=request.sid)

@socketio.on('start_typing')
@login_required
def handle_start_typing(data):
    recipient_sid = online_users.get(data.get('recipient_id'))
    if recipient_sid: emit('user_is_typing', {'username': current_user.username}, room=recipient_sid)

@socketio.on('stop_typing')
@login_required
def handle_stop_typing(data):
    recipient_sid = online_users.get(data.get('recipient_id'))
    if recipient_sid: emit('user_stopped_typing', {'username': current_user.username}, room=recipient_sid)

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)


---

## 2. File Client Đã Cập Nhật (client\_refactored\_final.py)

Không cần thay đổi trong client vì route `/files` sẽ tự động trả về dữ liệu đã được lọc.

```python
import sys
import os
import requests
import webbrowser
import socketio

from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit,
    QPushButton, QVBoxLayout, QMessageBox, QMainWindow,
    QListWidget, QFileDialog, QHBoxLayout,
    QSplitter, QListWidgetItem, QTabWidget, QDialog,
    QFormLayout, QDialogButtonBox, QCheckBox, QStyledItemDelegate,
    QSizePolicy, QGridLayout, QFrame
)
from PySide6.QtCore import Qt, QSize, Signal, QRect, QRunnable, QThreadPool, QTimer, QSettings, QObject
from PySide6.QtGui import QFont, QColor, QBrush, QPen, QPainter, QTextDocument, QIcon, QPixmap, QPainterPath

# --- Global Settings ---
API_SESSION = requests.Session()
# !!! IMPORTANT: Ensure this URL matches your server !!!
SERVER_URL = 'https://chat-app-fxps.onrender.com'
SIO_CLIENT = socketio.Client(http_session=API_SESSION)

# Hằng số phiên bản hiện tại của CLIENT
CURRENT_VERSION = "1.0.0" 

# Thiết lập Timeout cho các yêu cầu mạng ban đầu (cho phép Render khởi động)
DEFAULT_TIMEOUT = 60 

# --- Theme Definitions ---
# Định nghĩa bộ màu cho giao diện Tối
COLORS_DARK = {
    "bg_app": "#1e1e2d", "bg_primary": "#27293d", "bg_secondary": "#363a50",
    "text_main": "#e0e0e0", "text_header": "#ffffff", "accent": "#6a5acd", "text_on_accent": "#ffffff",
    "border_subtle": "#3e4157", "border_strong": "#525468", 
    "bubble_in": "#363a50", "bubble_out": "#6a5acd", "unread": "#ff79c6",
    "shadow": "rgba(0, 0, 0, 0.4)",
    "font_family": "Segoe UI, Arial"
}

# Định nghĩa bộ màu cho giao diện Sáng
COLORS_LIGHT = {
    "bg_app": "#f8f9fa", "bg_primary": "#ffffff", "bg_secondary": "#e9ecef",
    "text_main": "#343a40", "text_header": "#007bff", "accent": "#007bff", "text_on_accent": "#ffffff",
    "border_subtle": "#dee2e6", "border_strong": "#adb5bd", 
    "bubble_in": "#e9ecef", "bubble_out": "#007bff", "unread": "#dc3545",
    "shadow": "rgba(0, 0, 0, 0.1)",
    "font_family": "Segoe UI, Arial"
}

def get_stylesheet(colors):
    """Tạo stylesheet dựa trên bộ màu được chọn."""
    return f"""
        * {{ font-family: {colors['font_family']}; }}

        #MainWindow, #LoginWindow, #UpdateUploadDialog {{ 
            background-color: {colors['bg_app']}; 
        }}
        
        #leftPanel {{ 
            background-color: {colors['bg_primary']}; 
            border-right: 1px solid {colors['border_strong']};
        }}
        
        #rightPanel, QTabWidget::pane {{ 
            background-color: {colors['bg_app']}; 
            border: none; 
        }}
        
        QTabBar::tab {{ 
            background: {colors['bg_primary']}; 
            color: {colors['text_main']}; 
            padding: 10px 15px; 
            border: 1px solid {colors['border_strong']}; 
            border-bottom: none; 
            border-top-left-radius: 8px; 
            border-top-right-radius: 8px; 
            font-weight: 600;
        }}
        QTabBar::tab:selected {{ 
            background: {colors['bg_app']}; 
            color: {colors['text_header']}; 
            border-bottom: 1px solid {colors['bg_app']}; 
        }}
        
        QListWidget {{ 
            background-color: transparent; 
            border: none; 
            outline: 0; 
        }}
        
        QListWidget::item {{
            padding: 5px;
            border-radius: 6px;
            margin: 2px 0;
        }}
        QListWidget::item:selected {{
             background-color: {colors['bg_secondary']};
        }}

        QPushButton {{ 
            background-color: {colors['accent']}; 
            color: {colors['text_on_accent']}; 
            border: none; 
            padding: 12px 20px; 
            border-radius: 8px; 
            font-size: 14px; 
            font-weight: bold; 
            box-shadow: 0 4px 6px {colors['shadow']};
            transition: all 0.2s;
        }}
        QPushButton:hover {{ 
            background-color: {'#8B80FF' if colors == COLORS_DARK else '#0056b3'};
            box-shadow: 0 6px 10px {colors['shadow']};
        }}
        QPushButton:pressed {{
            background-color: {'#5a4fa3' if colors == COLORS_DARK else '#004085'};
        }}

        #deleteHistoryButton {{ 
            background-color: transparent; 
            color: {colors['text_main']};
            border: 1px solid {colors['border_strong']};
            padding: 8px 12px;
            border-radius: 6px;
            box-shadow: none;
        }}
        #deleteHistoryButton:hover {{
             background-color: {colors['bg_secondary']};
             color: {colors['text_header']};
        }}

        QLineEdit {{ 
            background-color: {colors['bg_secondary']}; 
            color: {colors['text_main']}; 
            border: 1px solid {colors['border_subtle']}; 
            padding: 12px; 
            border-radius: 8px; 
            font-size: 15px; 
        }}
        QLineEdit:focus {{
             border: 1px solid {colors['accent']}; 
        }}

        QLabel#titleLabel {{ 
            font-size: 28px; 
            font-weight: bold; 
            color: {colors['text_header']}; 
        }}
        QLabel#headerLabel, QLabel {{ 
            font-size: 14px; 
            color: {colors['text_main']}; 
        }}
        
        QScrollBar:vertical {{ 
            border: none; 
            background: {colors['bg_primary']}; 
            width: 10px; 
            margin: 0; 
        }}
        QScrollBar::handle:vertical {{ 
            background: {colors['border_strong']}; 
            min-height: 20px; 
            border-radius: 5px; 
        }}
        QCheckBox {{ color: {colors['text_main']}; }}
        
        QLabel#readyLabel {{
            font-size: 14px;
            font-weight: 500;
        }}
        
        #AvatarListWidget {{
            border: 1px solid {colors['border_subtle']};
            border-radius: 8px;
            padding: 5px;
            background-color: {colors['bg_secondary']};
        }}
        #AvatarListWidget::item {{
            margin: 5px;
            padding: 0;
        }}
    """

# --- UTILITY AND TASK CLASSES ---

class AvatarDownloader(QRunnable):
    """Downloads avatar in a separate thread and updates the widget."""
    def __init__(self, url, item_widget):
        super().__init__()
        self.url = url
        self.widget = item_widget

    def run(self):
        try:
            response = requests.get(self.url, stream=True)
            if response.ok:
                pixmap = QPixmap()
                pixmap.loadFromData(response.content)
                self.widget.set_avatar(pixmap)
        except Exception as e:
            print(f"Error downloading avatar: {e}")

class UserListItem(QWidget):
    """Custom widget for an item in the user list (avatar + username + unread badge)."""
    def __init__(self, username):
        super().__init__()
        colors = QApplication.instance().colors

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 15, 10, 15) 
        layout.setSpacing(10)

        self.avatar_label = QLabel()
        self.avatar_label.setFixedSize(40, 40)
        self.set_avatar(None)

        self.username_label = QLabel(username)
        self.username_label.setFont(QFont(colors['font_family'], 11, QFont.Bold))
        self.username_label.setStyleSheet(f"color: {colors['text_main']};")

        self.unread_badge = QLabel()
        self.unread_badge.setStyleSheet(f"background-color: {colors['unread']}; color: white; font-size: 10px; font-weight: bold; border-radius: 8px; padding: 2px 5px;")
        self.unread_badge.setMinimumWidth(16)
        self.unread_badge.setAlignment(Qt.AlignCenter)
        self.unread_badge.hide()

        layout.addWidget(self.avatar_label)
        layout.addWidget(self.username_label)
        layout.addStretch()
        layout.addWidget(self.unread_badge)

    def set_avatar(self, pixmap):
        size = 40
        colors = QApplication.instance().colors

        if pixmap is None or pixmap.isNull():
            pixmap = QPixmap(size, size)
            pixmap.fill(QColor(colors['accent']))

        scaled_pixmap = pixmap.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        target = QPixmap(size, size)
        target.fill(Qt.transparent)

        with QPainter(target) as painter:
            painter.setRenderHint(QPainter.Antialiasing)
            path = QPainterPath()
            path.addEllipse(0, 0, size, size)
            painter.setClipPath(path)
            
            x = (size - scaled_pixmap.width()) / 2
            y = (size - scaled_pixmap.height()) / 2
            painter.drawPixmap(int(x), int(y), scaled_pixmap)

        self.avatar_label.setPixmap(target)
        
    def sizeHint(self):
        return QSize(250, 70) 

class MessageDelegate(QStyledItemDelegate):
    """Custom delegate to draw chat bubbles and message status."""
    def paint(self, painter, option, index):
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        colors = QApplication.instance().colors

        is_mine = index.data(Qt.UserRole + 1)
        rich_text = index.data(Qt.DisplayRole)
        status = index.data(Qt.UserRole + 2)

        doc = QTextDocument()
        text_color = colors['text_on_accent'] if is_mine else colors['text_main']
        # Áp dụng font và màu cho nội dung tin nhắn
        styled_rich_text = f"<span style='color: {text_color}; font-family: {colors['font_family']}'>{rich_text}</span>"
        
        doc.setHtml(styled_rich_text)
        doc.setDefaultFont(option.font) 
        doc.setTextWidth(option.rect.width() * 0.65) # Giảm chiều rộng bubble một chút

        bubble_size = doc.size()
        bubble_width = bubble_size.width() + 20
        bubble_height = bubble_size.height() + 20
        status_height = 15 if is_mine and status else 0
        bubble_rect = QRect()

        if is_mine:
            # Align right
            bubble_rect.setRect(option.rect.right() - bubble_width - 15, option.rect.top() + 5, bubble_width, bubble_height)
            painter.setBrush(QBrush(QColor(colors['bubble_out'])))
        else:
            # Align left
            bubble_rect.setRect(option.rect.left() + 15, option.rect.top() + 5, bubble_width, bubble_height)
            painter.setBrush(QBrush(QColor(colors['bubble_in'])))

        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(bubble_rect, 10.0, 10.0) # Bo góc mềm mại hơn

        # Draw text content
        painter.translate(bubble_rect.left() + 10, bubble_rect.top() + 10)
        doc.drawContents(painter)
        painter.restore()

        # Draw status (e.g., "Đã gửi", "Đã xem")
        if status_height > 0:
            painter.save()
            status_rect = QRect(bubble_rect.left(), bubble_rect.bottom(), bubble_rect.width() - 5, status_height)
            painter.setPen(QColor(colors['text_main']))
            font = painter.font()
            font.setPointSize(8)
            font.setItalic(True)
            painter.setFont(font)
            painter.drawText(status_rect, Qt.AlignRight | Qt.AlignVCenter, status)
            painter.restore()

    def sizeHint(self, option, index):
        rich_text = index.data(Qt.DisplayRole)
        is_mine = index.data(Qt.UserRole + 1)
        status = index.data(Qt.UserRole + 2)
        colors = QApplication.instance().colors

        doc = QTextDocument()
        text_color = colors['text_on_accent'] if is_mine else colors['text_main']
        styled_rich_text = f"<span style='color: {text_color}; font-family: {colors['font_family']}'>{rich_text}</span>"
        doc.setHtml(styled_rich_text)
        doc.setTextWidth(option.rect.width() * 0.65)

        status_height = 15 if is_mine and status else 0
        # 25 = 5 (top margin) + 5 (bottom margin) + 10 (text top padding) + 5 (text bottom padding)
        return QSize(int(doc.size().width()), int(doc.size().height() + 25 + status_height))

class UserDialog(QDialog):
    """Dialog for Admin Panel to Add/Edit user details."""
    def __init__(self, parent=None, username="", is_admin=False):
        super().__init__(parent)
        self.setWindowTitle("Thông Tin User")
        self.setStyleSheet(QApplication.instance().styleSheet())
        layout = QFormLayout(self)

        self.username_input = QLineEdit(username)
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Để trống nếu không muốn đổi")
        self.is_admin_checkbox = QCheckBox()
        self.is_admin_checkbox.setChecked(is_admin)

        layout.addRow("Username:", self.username_input)
        layout.addRow("New Password:", self.password_input)
        layout.addRow("Is Admin:", self.is_admin_checkbox)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

    def get_data(self):
        return {
            "username": self.username_input.text(),
            "password": self.password_input.text(),
            "is_admin": self.is_admin_checkbox.isChecked()
        }

# --- AVATAR SELECTION DIALOG ---
class AvatarSelectDialog(QDialog):
    """Dialog hiển thị lưới avatar đã tải lên để người dùng chọn."""
    def __init__(self, parent=None, avatars=None):
        super().__init__(parent)
        self.setWindowTitle("Chọn Avatar đã tải lên")
        self.setMinimumSize(450, 400)
        self.selected_public_id = None
        self.setStyleSheet(QApplication.instance().styleSheet())
        
        main_layout = QVBoxLayout(self)
        
        self.avatar_list = QListWidget()
        self.avatar_list.setObjectName("AvatarListWidget")
        self.avatar_list.setFlow(QListWidget.LeftToRight)
        self.avatar_list.setWrapping(True)
        self.avatar_list.setViewMode(QListWidget.IconMode)
        self.avatar_list.setIconSize(QSize(100, 100))
        self.avatar_list.setResizeMode(QListWidget.Adjust)
        self.avatar_list.setGridSize(QSize(110, 110))
        self.avatar_list.setMovement(QListWidget.Static)
        
        if avatars:
            self.load_avatars(avatars)

        self.avatar_list.currentItemChanged.connect(self.selection_changed)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept_selection)
        self.buttons.rejected.connect(self.reject)
        self.buttons.button(QDialogButtonBox.Ok).setDisabled(True)

        main_layout.addWidget(self.avatar_list)
        main_layout.addWidget(self.buttons)
        
    def load_avatars(self, avatars):
        self.avatar_list.clear()
        for avatar in avatars:
            item = QListWidgetItem()
            item.setData(Qt.UserRole, avatar['public_id'])
            
            pixmap = QPixmap()
            try:
                response = requests.get(avatar['url'], timeout=5) 
                if response.ok:
                    pixmap.loadFromData(response.content)
                    item.setIcon(QIcon(pixmap.scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)))
                
                self.avatar_list.addItem(item)
            except Exception as e:
                print(f"Lỗi tải avatar thumbnail: {e}")
            
    def selection_changed(self, current, previous):
        if current:
            self.selected_public_id = current.data(Qt.UserRole)
            self.buttons.button(QDialogButtonBox.Ok).setDisabled(False)
        else:
            self.selected_public_id = None
            self.buttons.button(QDialogButtonBox.Ok).setDisabled(True)

    def accept_selection(self):
        if self.selected_public_id:
            self.accept()
        else:
            QMessageBox.warning(self, "Lưu ý", "Vui lòng chọn một avatar.")
            
    def get_selected_public_id(self):
        return self.selected_public_id

# --- UPDATE UPLOAD DIALOG ---
class UpdateUploadDialog(QDialog):
    """Dialog cho phép Admin tải lên file client mới và gán số phiên bản."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Tải lên Bản cập nhật Client")
        self.setObjectName("UpdateUploadDialog")
        self.setStyleSheet(QApplication.instance().styleSheet())
        self.file_path = None

        layout = QFormLayout(self)
        
        self.version_input = QLineEdit()
        self.version_input.setPlaceholderText("Ví dụ: 1.1.0")
        
        self.file_path_label = QLabel("Chưa chọn file...")
        self.file_button = QPushButton("Chọn File (.exe/.zip)")
        self.file_button.clicked.connect(self.select_file)

        layout.addRow("Số phiên bản:", self.version_input)
        layout.addRow("File:", self.file_path_label)
        layout.addRow("", self.file_button)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.upload_update)
        self.buttons.rejected.connect(self.reject)
        self.buttons.button(QDialogButtonBox.Ok).setText("Tải lên & Kích hoạt")
        
        layout.addWidget(self.buttons)

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Chọn File Cập nhật", "", "Client Files (*.exe *.zip);;All Files (*.*)")
        if file_path:
            self.file_path = file_path
            self.file_path_label.setText(os.path.basename(file_path))

    def upload_update(self):
        version = self.version_input.text().strip()
        if not version or not self.file_path:
            QMessageBox.warning(self, "Lỗi", "Vui lòng nhập số phiên bản và chọn file."); return

        try:
            with open(self.file_path, 'rb') as f:
                # Gửi file và version number
                files = {'update_file': (os.path.basename(self.file_path), f)}
                data = {'version_number': version}
                
                QMessageBox.information(self, "Đang tải", "Đang tải lên file cập nhật. Vui lòng đợi...", QMessageBox.NoButton)
                
                response = API_SESSION.post(f"{SERVER_URL}/admin/upload-update", files=files, data=data, timeout=300) # Timeout dài hơn cho file lớn
                response.raise_for_status()
                
                QMessageBox.information(self, "Thành công", response.json().get('message'))
                self.accept()
                
        except Exception as e:
            QMessageBox.critical(self, "Lỗi Upload", f"Không thể tải lên bản cập nhật: {e}")
            self.reject()
            

# --- SOCKETIO AND TASK CLASSES ---
class SocketIOManager(QObject): 
    """Quản lý kết nối SocketIO và phát tín hiệu cho MainWindow."""
    
    def __init__(self, sio_client, message_signal, status_signal, typing_signal, stop_typing_signal, seen_signal, offline_signal):
        super().__init__()
        self.sio_client = sio_client
        self.message_signal = message_signal
        self.status_signal = status_signal
        self.typing_signal = typing_signal
        self.stop_typing_signal = stop_typing_signal
        self.seen_signal = seen_signal
        self.offline_signal = offline_signal
        self._setup_events()

    def _setup_events(self):
        sio = self.sio_client
        
        @sio.on('connect')
        def on_connect():
            print("Connected to chat server!")

        @sio.on('offline_notifications')
        def on_offline_notifications(data):
            self.offline_signal.emit(data.get('counts', {}))

        @sio.on('message_from_server')
        def on_message(data):
            self.message_signal.emit(data)

        @sio.on('message_status_update')
        def on_status_update(data):
            self.status_signal.emit(data['id'], data['status'])

        @sio.on('messages_seen')
        def on_messages_seen(data):
            self.seen_signal.emit(data['ids'])

        @sio.on('user_is_typing')
        def on_typing(data):
            self.typing_signal.emit(data['username'])

        @sio.on('user_stopped_typing')
        def on_stop_typing(data):
            self.stop_typing_signal.emit(data['username'])

class ConnectionSignals(QObject):
    finished = Signal(dict)
    error = Signal(str)

class ConnectionTask(QRunnable):
    def __init__(self, user_info, parent_window):
        super().__init__()
        self.signals = ConnectionSignals()
        self.user_info = user_info
        self.parent_window = parent_window

    def run(self):
        # Mở kết nối SocketIO (TÁC VỤ 1)
        try:
            if not SIO_CLIENT.connected:
                SIO_CLIENT.connect(SERVER_URL, wait_timeout=DEFAULT_TIMEOUT) 
        except Exception as e:
            self.signals.error.emit(f"Không thể kết nối SocketIO: {e}")
            return
            
        # Lấy danh sách người dùng đầu tiên (TÁC VỤ 2)
        try:
            response = API_SESSION.get(f"{SERVER_URL}/online-users", timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            users_data = response.json()
        except requests.exceptions.Timeout:
            self.signals.error.emit("Lỗi Timeout: Server không phản hồi kịp thời khi tải danh sách người dùng.")
            return
        except Exception as e:
            self.signals.error.emit(f"Không thể tải danh sách người dùng (kiểm tra server logs): {e}")
            return
            
        self.signals.finished.emit(users_data)

class WakeupSignals(QObject):
    finished = Signal(bool)

class WakeupTask(QRunnable):
    def __init__(self):
        super().__init__()
        self.signals = WakeupSignals()

    def run(self):
        try:
            response = requests.get(SERVER_URL, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            self.signals.finished.emit(True)
        except requests.exceptions.Timeout:
            self.signals.finished.emit(False)
        except Exception as e:
            self.signals.finished.emit(False)
            
class LoginTaskSignals(QObject):
    finished = Signal(dict)
    error = Signal(str)

class LoginTaskRunner(QRunnable):
    def __init__(self, username, password):
        super().__init__()
        self.username = username
        self.password = password
        self.signals = LoginTaskSignals()

    def run(self):
        try:
            response = API_SESSION.post(f'{SERVER_URL}/login', json={'username': self.username, 'password': self.password}, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            
            self.signals.finished.emit(data)
            
        except requests.exceptions.Timeout:
            self.signals.error.emit(f"Lỗi Timeout (60s): Server Render quá chậm để khởi động. Vui lòng thử lại sau.")
            
        except requests.exceptions.HTTPError as e:
            error_message = "Sai tên đăng nhập hoặc mật khẩu." 
            if e.response.status_code != 401:
                 try:
                    error_data = e.response.json()
                    error_message = error_data.get('message', 'Lỗi server không xác định.')
                 except:
                    error_message = f"Lỗi HTTP {e.response.status_code}. Server đã phản hồi nhưng có lỗi (Kiểm tra logs server)."
            self.signals.error.emit(error_message)
            
        except Exception as e:
            self.signals.error.emit(f"Không thể kết nối đến địa chỉ server: {type(e).__name__} - {e}")

class UpdateSignals(QObject):
    update_available = Signal(str, str) # version, url
    no_update = Signal()

class UpdateChecker(QRunnable):
    """Kiểm tra phiên bản mới nhất từ server."""
    def __init__(self, current_version):
        super().__init__()
        self.signals = UpdateSignals()
        self.current_version = current_version

    def run(self):
        try:
            response = API_SESSION.get(f"{SERVER_URL}/update", timeout=5) 
            response.raise_for_status()
            data = response.json()
            latest_version = data.get('latest_version')
            download_url = data.get('download_url')
            
            if latest_version and download_url:
                current_v = tuple(map(int, self.current_version.split('.')))
                latest_v = tuple(map(int, latest_version.split('.')))
                
                if latest_v > current_v:
                    self.signals.update_available.emit(latest_version, download_url)
                    return
            
            self.signals.no_update.emit()
            
        except Exception as e:
            print(f"Lỗi khi kiểm tra cập nhật: {e}")
            self.signals.no_update.emit()

# --- Main Application Window ---
class MainWindow(QMainWindow):
    message_received_signal = Signal(dict)
    status_update_signal = Signal(str, str) # msg_id, status
    messages_seen_signal = Signal(list) # list of msg_ids
    user_typing_signal = Signal(str) # username
    user_stopped_typing_signal = Signal(str) # username
    offline_notifications_signal = Signal(dict) # counts dict
    
    # DI CHUYỂN PHƯƠNG THỨC THEME LÊN TRÊN __init__
    def apply_theme(self, theme_name):
        """Áp dụng stylesheet cho toàn bộ ứng dụng."""
        if theme_name == 'dark':
            colors = COLORS_DARK
            stylesheet = get_stylesheet(colors)
        else: # light
            colors = COLORS_LIGHT
            stylesheet = get_stylesheet(colors)

        QApplication.instance().colors = colors
        self.setStyleSheet(stylesheet)
        QApplication.instance().setStyleSheet(stylesheet)
        self.settings.setValue('theme', theme_name)
        self.current_theme = theme_name
        
        if hasattr(self, 'all_users_list'):
             self.update_user_list_styles()
        if hasattr(self, 'profile_avatar'):
            self.update_profile_avatar(self.user_info.get('avatar_url'))

    def toggle_theme(self):
        """Chuyển đổi giữa Light và Dark theme."""
        new_theme = 'light' if self.current_theme == 'dark' else 'dark'
        self.apply_theme(new_theme)
        
        if hasattr(self, 'theme_button'):
            self.theme_button.setText(f"Chuyển sang Giao diện {'Tối' if new_theme == 'light' else 'Sáng'}")


    def __init__(self, user_info):
        super().__init__()
        self.setObjectName("MainWindow")
        self.user_info = user_info
        username = user_info['username']

        self.setWindowTitle(f"App Đa Năng - Chào mừng {username} (v{CURRENT_VERSION})")
        self.setWindowIcon(QIcon("icon.png"))
        self.resize(1100, 800)
        
        self.settings = QSettings('MyApp', 'ChatClient')
        
        self.current_theme = self.settings.value('theme', 'dark')
        
        # GỌI PHƯƠNG THỨC apply_theme SAU KHI ĐÃ ĐƯỢC ĐỊNH NGHĨA
        self.apply_theme(self.current_theme)

        # State Variables
        self.current_chat_partner = None
        self.unread_counts = {}
        self.message_statuses = {}
        self.is_typing = False 
        
        # Utilities
        self.thread_pool = QThreadPool()
        self.chat_delegate = MessageDelegate(self)

        # Setup UI 
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self._setup_tabs()
        
        # Setup Network
        self.message_received_signal.connect(self.handle_new_message)
        self.status_update_signal.connect(lambda id, status: self.update_message_status(id, status))
        self.messages_seen_signal.connect(self.handle_messages_seen)
        self.user_typing_signal.connect(self.handle_user_typing)
        self.user_stopped_typing_signal.connect(self.handle_user_stopped_typing)
        self.offline_notifications_signal.connect(self.handle_offline_notifications)
        
        # Khởi tạo SocketIO Manager
        self.sio_manager = SocketIOManager(
            SIO_CLIENT, self.message_received_signal, self.status_update_signal,
            self.user_typing_signal, self.user_stopped_typing_signal, 
            self.messages_seen_signal, self.offline_notifications_signal
        )
        
        # Bắt đầu Task kết nối SIO và tải danh sách người dùng trong nền
        self.start_initial_connection_task()
        
        # KIỂM TRA CẬP NHẬT NGAY SAU KHI ỨNG DỤNG KHỞI ĐỘNG
        self.check_for_updates()
        
    def check_for_updates(self):
        """Khởi chạy checker cập nhật trong luồng nền."""
        checker = UpdateChecker(CURRENT_VERSION)
        checker.signals.update_available.connect(self.handle_update_available)
        self.thread_pool.start(checker)

    def handle_update_available(self, version, url):
        """Xử lý khi có phiên bản mới."""
        reply = QMessageBox.information(self, "Cập nhật mới", 
                                        f"Phiên bản mới ({version}) đã có sẵn. Bạn có muốn tải xuống và cập nhật không?\n\n(Lưu ý: Ứng dụng cần khởi động lại.)",
                                        QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if reply == QMessageBox.Yes:
            self.download_and_restart(url)

    def download_and_restart(self, url):
        """Hướng dẫn người dùng tải file mới và khởi động lại."""
        QMessageBox.information(self, "Tải cập nhật", 
                                "Trình duyệt sẽ mở để bạn tải file cập nhật. Vui lòng đóng ứng dụng này sau khi tải xong và chạy file mới.",
                                QMessageBox.Ok)
        webbrowser.open(url)
        
    def start_initial_connection_task(self):
        """Bắt đầu task kết nối SIO và tải data ban đầu trong luồng nền."""
        task = ConnectionTask(self.user_info, self)
        task.signals.finished.connect(self.handle_initial_connection_success)
        task.signals.error.connect(self.handle_initial_connection_error)
        self.thread_pool.start(task)

    def handle_initial_connection_success(self, users_data):
        """Xử lý kết nối thành công và tải dữ liệu người dùng."""
        self.update_all_users_from_data(users_data)
        self.all_users_list.setMinimumHeight(0) 

    def handle_initial_connection_error(self, error_message):
        """Xử lý lỗi trong quá trình kết nối SIO/tải data."""
        QMessageBox.critical(self, "Lỗi Kết Nối", error_message)
        self.all_users_list.clear()
        self.all_users_list.setMinimumHeight(50)
        error_item = QListWidgetItem("Không thể kết nối hoặc tải dữ liệu.")
        self.all_users_list.addItem(error_item)

    # --- UI Creation Methods ---
    def _setup_tabs(self):
        """Creates and adds all tabs to the main window."""
        self.tabs.addTab(self.create_chat_tab(), "Chat")
        self.tabs.addTab(self.create_files_tab(), "Quản Lý File")
        self.tabs.addTab(self.create_profile_tab(), "Hồ sơ")
        if self.user_info.get('is_admin', False):
            self.tabs.addTab(self.create_admin_tab(), "Admin Panel")

    def create_chat_tab(self):
        chat_widget = QWidget()
        main_layout = QHBoxLayout(chat_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Left Panel (User List)
        left_panel = QWidget(); left_panel.setObjectName("leftPanel")
        left_layout = QVBoxLayout(left_panel); left_panel.setFixedWidth(300)
        self.search_input = QLineEdit(); self.search_input.setPlaceholderText("Tìm kiếm người dùng...")
        self.all_users_list = QListWidget()
        # Hiển thị placeholder tải khi khởi tạo
        self.all_users_list.setMinimumHeight(100) 
        self.all_users_list.clear()
        self.all_users_list.addItem(QListWidgetItem("Đang tải danh sách người dùng..."))
        self.all_users_list.item(0).setFlags(Qt.NoItemFlags) # Không cho phép chọn placeholder
        
        left_layout.addWidget(QLabel("Tất Cả Người Dùng:"))
        left_layout.addWidget(self.search_input)
        left_layout.addWidget(self.all_users_list)

        # Right Panel (Chat History & Input)
        right_panel = QWidget(); right_panel.setObjectName("rightPanel")
        right_layout = QVBoxLayout(right_panel); right_layout.setContentsMargins(10, 10, 10, 10)
        self.chat_with_label = QLabel("Hãy chọn một người để bắt đầu chat"); self.chat_with_label.setObjectName("headerLabel")
        self.delete_history_button = QPushButton("Xóa Lịch sử"); self.delete_history_button.setFixedWidth(120)
        top_bar = QHBoxLayout(); top_bar.addWidget(self.chat_with_label); top_bar.addStretch(); top_bar.addWidget(self.delete_history_button)
        self.chat_history_list = QListWidget(); self.chat_history_list.setItemDelegate(self.chat_delegate)
        self.typing_indicator_label = QLabel(" "); self.typing_indicator_label.setFixedHeight(20)
        self.message_input = QLineEdit(); self.message_input.setPlaceholderText("Nhập tin nhắn...")
        self.send_button = QPushButton("Gửi")
        input_layout = QHBoxLayout(); input_layout.addWidget(self.message_input); input_layout.addWidget(self.send_button)

        right_layout.addLayout(top_bar)
        right_layout.addWidget(self.chat_history_list)
        right_layout.addWidget(self.typing_indicator_label)
        right_layout.addLayout(input_layout)

        main_layout.addWidget(left_panel)
        main_layout.addWidget(right_panel)

        # Connections
        self.search_input.textChanged.connect(self.filter_user_list)
        self.send_button.clicked.connect(self.send_message)
        self.message_input.returnPressed.connect(self.send_message)
        self.message_input.textChanged.connect(self.handle_message_input_change) 
        self.all_users_list.currentItemChanged.connect(self.select_chat_partner)
        self.delete_history_button.clicked.connect(self.delete_history)

        return chat_widget

    def create_files_tab(self):
        files_widget = QWidget(); layout = QVBoxLayout(files_widget); self.file_list_widget = QListWidget()
        button_layout = QHBoxLayout(); self.upload_button = QPushButton("Tải Lên"); self.download_button = QPushButton("Tải Về"); self.refresh_button = QPushButton("Làm Mới")
        button_layout.addWidget(self.upload_button); button_layout.addWidget(self.download_button)
        if self.user_info.get('is_admin', False): self.delete_button = QPushButton("Xóa"); button_layout.addWidget(self.delete_button); self.delete_button.clicked.connect(self.delete_file)
        button_layout.addWidget(self.refresh_button)
        layout.addWidget(QLabel("Tất cả file trong hệ thống:")); layout.addWidget(self.file_list_widget); layout.addLayout(button_layout)
        self.upload_button.clicked.connect(self.upload_file); self.download_button.clicked.connect(self.download_file); self.refresh_button.clicked.connect(self.refresh_files)
        self.refresh_files(); return files_widget
        
    def create_admin_tab(self):
        admin_widget = QWidget(); layout = QVBoxLayout(admin_widget); self.admin_user_list = QListWidget()
        
        # Thêm nút Tải lên bản cập nhật vào Admin Panel
        self.upload_update_button = QPushButton("Tải lên Bản cập nhật Client")
        self.upload_update_button.clicked.connect(lambda: UpdateUploadDialog(self).exec())

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.upload_update_button)
        self.admin_add_button = QPushButton("Thêm User"); self.admin_edit_button = QPushButton("Sửa User"); self.admin_delete_button = QPushButton("Xóa User"); self.admin_refresh_button = QPushButton("Làm Mới")
        button_layout.addWidget(self.admin_add_button); button_layout.addWidget(self.admin_edit_button); button_layout.addWidget(self.admin_delete_button); button_layout.addWidget(self.admin_refresh_button)
        
        layout.addWidget(QLabel("Quản Lý Tất Cả Người Dùng:")); 
        layout.addWidget(self.admin_user_list); 
        layout.addLayout(button_layout)
        
        self.admin_add_button.clicked.connect(self.add_user_admin); self.admin_edit_button.clicked.connect(self.edit_user_admin); self.admin_delete_button.clicked.connect(self.delete_user_admin); self.admin_refresh_button.clicked.connect(self.refresh_users_admin)
        self.refresh_users_admin(); return admin_widget

    def create_profile_tab(self):
        profile_widget = QWidget(); 
        layout = QVBoxLayout(profile_widget); 
        layout.setAlignment(Qt.AlignCenter); 
        layout.setSpacing(20)
        
        self.profile_avatar = QLabel(); 
        self.profile_avatar.setFixedSize(100, 100)
        self.update_profile_avatar(self.user_info.get('avatar_url'))
        
        upload_button = QPushButton("Tải lên Avatar mới"); 
        upload_button.clicked.connect(self.upload_avatar); 
        upload_button.setFixedWidth(200)

        self.select_avatar_button = QPushButton("Chọn Avatar đã tải lên");
        self.select_avatar_button.clicked.connect(self.open_avatar_selection_dialog);
        self.select_avatar_button.setFixedWidth(200)
        
        theme_text = "Chuyển sang Giao diện Sáng" if self.current_theme == 'dark' else "Chuyển sang Giao diện Tối"
        self.theme_button = QPushButton(theme_text)
        self.theme_button.clicked.connect(self.toggle_theme)
        self.theme_button.setFixedWidth(200)

        button_layout = QVBoxLayout()
        button_layout.addWidget(upload_button, 0, Qt.AlignCenter)
        button_layout.addWidget(self.select_avatar_button, 0, Qt.AlignCenter)
        button_layout.addWidget(self.theme_button, 0, Qt.AlignCenter)

        layout.addWidget(self.profile_avatar, 0, Qt.AlignCenter); 
        layout.addLayout(button_layout)
        
        return profile_widget
    
    # --- Avatar/Profile Methods ---
    def open_avatar_selection_dialog(self):
        """Mở dialog cho phép người dùng chọn avatar đã tải lên."""
        try:
            # 1. Tải danh sách các avatar đã tải lên từ server
            response = API_SESSION.get(f"{SERVER_URL}/avatars", timeout=10)
            response.raise_for_status()
            avatars = response.json().get('avatars', [])
            
            if not avatars:
                QMessageBox.information(self, "Lưu ý", "Bạn chưa tải lên bất kỳ avatar nào trước đó.")
                return

            # 2. Khởi tạo và hiển thị dialog
            dialog = AvatarSelectDialog(self, avatars)
            if dialog.exec():
                selected_public_id = dialog.get_selected_public_id()
                if selected_public_id:
                    self.set_new_avatar_from_public_id(selected_public_id)

        except Exception as e:
            QMessageBox.critical(self, "Lỗi Tải Avatar", f"Không thể tải danh sách avatar: {e}")

    def set_new_avatar_from_public_id(self, public_id):
        """Gọi server để đặt public_id được chọn làm avatar chính thức."""
        try:
            response = API_SESSION.post(f"{SERVER_URL}/avatar/select", json={'public_id': public_id}, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            self.user_info['avatar_url'] = data.get('avatar_url')
            self.update_profile_avatar(data.get('avatar_url'))
            self.update_all_users_manually()
            QMessageBox.information(self, "Thành công", "Avatar đã được cập nhật.")
        except Exception as e:
            QMessageBox.critical(self, "Lỗi Đặt Avatar", f"Không thể đặt avatar: {e}")
            
    def upload_avatar(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Chọn ảnh đại diện", "", "Image Files (*.png *.jpg *.jpeg)")
        if not file_path:
            return
        try:
            with open(file_path, 'rb') as f:
                files = {'avatar': f}
                response = API_SESSION.post(f"{SERVER_URL}/avatar/upload", files=files, timeout=10)
                response.raise_for_status()
                data = response.json()
                self.user_info['avatar_url'] = data.get('avatar_url')
                self.update_profile_avatar(data.get('avatar_url'))
                self.update_all_users_manually() 
                QMessageBox.information(self, "Thành công", "Avatar đã được cập nhật.")
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Không thể tải lên avatar: {e}")

    def update_profile_avatar(self, url):
        size = 100
        colors = QApplication.instance().colors
        
        pixmap = QPixmap(size, size)
        pixmap.fill(QColor(colors['bg_app']))

        if url:
            try:
                response = requests.get(url, stream=True)
                if response.ok:
                    pixmap.loadFromData(response.content)
            except Exception as e:
                print(f"Lỗi tải avatar cá nhân: {e}")

        scaled_pixmap = pixmap.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        target = QPixmap(size, size)
        target.fill(Qt.transparent)

        with QPainter(target) as painter:
            painter.setRenderHint(QPainter.Antialiasing)
            path = QPainterPath()
            path.addEllipse(0, 0, size, size)
            painter.setClipPath(path)
            
            x = (size - scaled_pixmap.width()) / 2
            y = (size - scaled_pixmap.height()) / 2
            painter.drawPixmap(int(x), int(y), scaled_pixmap)

        self.profile_avatar.setPixmap(target)

    # --- Chat Logic Methods ---
    def handle_message_input_change(self, text):
        if not self.current_chat_partner:
            return

        recipient_id = self.current_chat_partner['id']
        text_length = len(text)

        if text_length > 0 and not self.is_typing:
            self.is_typing = True
            SIO_CLIENT.emit('start_typing', {'recipient_id': recipient_id})
        elif text_length == 0 and self.is_typing:
            self.stop_typing_emit()

    def stop_typing_emit(self):
        """Emits 'stop_typing' and resets the typing state."""
        if self.is_typing and self.current_chat_partner:
            self.is_typing = False
            SIO_CLIENT.emit('stop_typing', {'recipient_id': self.current_chat_partner['id']})
    
    def send_message(self, clear_input=True):
        """Sends the message and clears the input."""
        
        if self.is_typing:
            self.stop_typing_emit()

        message = self.message_input.text()
        if message and self.current_chat_partner:
            SIO_CLIENT.emit('private_message', {'recipient_id': self.current_chat_partner['id'], 'message': message})
            if clear_input:
                self.message_input.clear()

    def select_chat_partner(self, current, previous):
        """Loads chat history when a user is selected."""
        if not current:
            return

        user_id = current.data(Qt.UserRole)
        username = current.data(Qt.UserRole + 1)
        self.current_chat_partner = {'id': user_id, 'username': username}
        self.chat_with_label.setText(f"Trò chuyện với {username}")
        self.chat_history_list.clear()
        self.message_statuses.clear()

        if username in self.unread_counts:
            del self.unread_counts[username]
            self.update_user_list_styles()
        
        try:
            # Thêm timeout cho request lịch sử
            response = API_SESSION.get(f"{SERVER_URL}/history/{user_id}", timeout=10)
            response.raise_for_status()
            for msg in response.json():
                if msg['sender'] == self.user_info['username'] and msg.get('is_read'):
                    self.message_statuses[msg['id']] = "Đã xem"
                self.add_item_to_chat(msg)
        except Exception as e:
            print(f"Không thể tải lịch sử chat: {e}")
            
    def add_item_to_chat(self, data):
        """Adds a message item to the chat history list."""
        item = QListWidgetItem()
        item.setData(Qt.DisplayRole, f"<b>{data['sender']}</b>:<br>{data['message']}") 
        item.setData(Qt.UserRole, data['sender']) 
        is_mine = data['sender'] == self.user_info['username']
        item.setData(Qt.UserRole + 1, is_mine)
        msg_id = data['id']
        item.setData(Qt.UserRole + 3, msg_id)

        if is_mine and msg_id not in self.message_statuses:
            self.message_statuses[msg_id] = "Đã gửi"

        item.setData(Qt.UserRole + 2, self.message_statuses.get(msg_id))
        self.chat_history_list.addItem(item)
        self.chat_history_list.scrollToBottom()

    def handle_new_message(self, data):
        """Handles the message_received_signal."""
        sender = data['sender']
        is_mine = (sender == self.user_info['username'])
        current_partner_name = self.current_chat_partner['username'] if self.current_chat_partner else None
        
        if not is_mine and sender != current_partner_name:
            self.unread_counts[sender] = self.unread_counts.get(sender, 0) + 1
            self.update_user_list_styles()
        
        if sender == current_partner_name or is_mine:
            self.add_item_to_chat(data)

    def update_message_status(self, msg_id, status):
        """Updates the status of a specific message item (e.g., 'Đã gửi' -> 'Đã xem')."""
        self.message_statuses[msg_id] = status
        for i in range(self.chat_history_list.count()):
            item = self.chat_history_list.item(i)
            if item and item.data(Qt.UserRole + 3) == msg_id:
                item.setData(Qt.UserRole + 2, status)
                self.chat_history_list.itemChanged.emit(item)
                break
                
    def handle_messages_seen(self, msg_ids):
        """Xử lý sự kiện nhiều tin nhắn được đánh dấu là đã xem."""
        for msg_id in msg_ids:
            self.update_message_status(msg_id, "Đã xem")

    def handle_user_typing(self, username):
        """Xử lý sự kiện người dùng đang soạn tin."""
        if self.current_chat_partner and username == self.current_chat_partner['username']:
            self.typing_indicator_label.setText(f"<i>{username} đang soạn tin...</i>")
            
    def handle_user_stopped_typing(self, username):
        """Xử lý sự kiện người dùng dừng soạn tin."""
        if self.current_chat_partner and username == self.current_chat_partner['username']:
            self.typing_indicator_label.setText(" ")
            
    def handle_offline_notifications(self, counts):
        """Xử lý thông báo tin nhắn chưa đọc khi offline."""
        self.unread_counts = counts
        self.update_user_list_styles()

    def update_all_users_from_data(self, users_data):
        """Cập nhật danh sách người dùng từ dữ liệu đã tải trong luồng nền."""
        self.all_users_list.clear()
        self.all_users_list.setMinimumHeight(0) # Xóa placeholder height

        for user in users_data.get('users', []):
            if user['id'] != self.user_info.get('user_id'):
                user_widget = UserListItem(user['username'])
                item = QListWidgetItem()
                item.setSizeHint(user_widget.sizeHint())
                item.setData(Qt.UserRole, user['id'])       # User ID
                item.setData(Qt.UserRole + 1, user['username']) # Username
                self.all_users_list.addItem(item)
                self.all_users_list.setItemWidget(item, user_widget)

                if user.get('avatar_url'):
                    downloader = AvatarDownloader(user['avatar_url'], self.all_users_list.itemWidget(item))
                    self.thread_pool.start(downloader)
        self.update_user_list_styles()
        
    def update_all_users_manually(self):
        """Hàm API cũ, được giữ lại để cập nhật sau khi upload avatar."""
        try:
            response = API_SESSION.get(f"{SERVER_URL}/online-users", timeout=10)
            response.raise_for_status()
            self.update_all_users_from_data(response.json())
        except Exception as e:
            print(f"Could not fetch user list: {e}")


    def update_user_list_styles(self):
        """Updates bolding and unread badges based on unread_counts."""
        for i in range(self.all_users_list.count()):
            item = self.all_users_list.item(i)
            widget = self.all_users_list.itemWidget(item)
            if widget:
                username = widget.username_label.text()
                count = self.unread_counts.get(username, 0)
                
                # Update font bolding
                font = widget.username_label.font()
                font.setBold(count > 0)
                widget.username_label.setFont(font)
                
                # Update unread badge
                if count > 0:
                    widget.unread_badge.setText(str(count))
                    widget.unread_badge.show()
                else:
                    widget.unread_badge.hide()

    def filter_user_list(self):
        """Filters the user list based on search input."""
        filter_text = self.search_input.text().lower()
        for i in range(self.all_users_list.count()):
            item = self.all_users_list.item(i)
            username = item.data(Qt.UserRole + 1).lower()
            item.setHidden(filter_text not in username)

    def setup_socketio_events(self):
        pass
        
    def closeEvent(self, event):
        if SIO_CLIENT.connected: SIO_CLIENT.disconnect()
        event.accept()

    def delete_history(self):
        if not self.current_chat_partner: QMessageBox.warning(self, "Lưu ý", "Vui lòng chọn một người dùng để xóa lịch sử chat."); return
        partner = self.current_chat_partner
        reply = QMessageBox.question(self, 'Xác nhận', f"Bạn có chắc muốn xóa toàn bộ lịch sử chat với '{partner['username']}' không?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            try: 
                response = API_SESSION.delete(f"{SERVER_URL}/history/{partner['id']}")
                response.raise_for_status()
                QMessageBox.information(self, "Thành công", response.json().get('message'))
                self.chat_history_list.clear()
            except Exception as e: QMessageBox.critical(self, "Lỗi", f"Không thể xóa lịch sử: {e}")
                
    def refresh_files(self): 
        try:
            # Route /files đã được sửa để chỉ hiển thị file của người dùng
            response = API_SESSION.get(f"{SERVER_URL}/files")
            response.raise_for_status()
            self.file_list_widget.clear()
            files = response.json().get('files', [])
            for file_info in files: 
                item = QListWidgetItem(file_info['filename'])
                item.setData(Qt.UserRole, file_info['public_id'])
                self.file_list_widget.addItem(item)
        except Exception as e: QMessageBox.warning(self, "Lỗi", f"Không thể tải danh sách file: {e}")
            
    def upload_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Chọn file")
        if not file_path: return
        try:
            with open(file_path, 'rb') as f: 
                files = {'file': (os.path.basename(file_path), f)}
                response = API_SESSION.post(f"{SERVER_URL}/upload", files=files)
                response.raise_for_status()
            QMessageBox.information(self, "Thông báo", response.json().get('message'))
            self.refresh_files()
        except Exception as e: QMessageBox.critical(self, "Lỗi", f"Không thể upload: {e}")
            
    def download_file(self):
        selected = self.file_list_widget.currentItem()
        if not selected: QMessageBox.warning(self, "Lưu ý", "Hãy chọn một file."); return
        public_id = selected.data(Qt.UserRole)
        try:
            response = API_SESSION.get(f"{SERVER_URL}/download/{public_id}")
            response.raise_for_status()
            download_url = response.json().get('download_url')
            if download_url: webbrowser.open(download_url)
            else: QMessageBox.warning(self, "Lỗi", "Không nhận được URL tải xuống.")
        except Exception as e: QMessageBox.critical(self, "Lỗi", f"Không thể lấy link tải file: {e}")
            
    def delete_file(self):
        selected = self.file_list_widget.currentItem()
        if not selected: QMessageBox.warning(self, "Lưu ý", "Hãy chọn một file."); return
        public_id = selected.data(Qt.UserRole); filename = selected.text()
        reply = QMessageBox.question(self, 'Xác nhận', f"Xóa file '{filename}'?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            try: 
                url = f"{SERVER_URL}/delete-file"; response = API_SESSION.post(url, json={'public_id': public_id})
                response.raise_for_status()
                QMessageBox.information(self, "Thông báo", response.json().get('message')); self.refresh_files()
            except Exception as e: QMessageBox.critical(self, "Lỗi", f"Không thể xóa: {e}")
                
    def refresh_users_admin(self):
        try:
            response = API_SESSION.get(f"{SERVER_URL}/admin/users")
            response.raise_for_status()
            self.admin_user_list.clear()
            users = response.json().get('users', [])
            for user in users: 
                item_text = f"{user['username']} {'(Admin)' if user['is_admin'] else ''}"
                item = QListWidgetItem(item_text); item.setData(Qt.UserRole, user['id']); self.admin_user_list.addItem(item)
        except Exception as e: QMessageBox.warning(self, "Lỗi", f"Không thể tải danh sách người dùng: {e}")
            
    def add_user_admin(self):
        dialog = UserDialog(self)
        if dialog.exec():
            data = dialog.get_data()
            try: 
                response = API_SESSION.post(f"{SERVER_URL}/admin/users", json=data)
                response.raise_for_status()
                QMessageBox.information(self, "Kết quả", response.json().get('message')); self.refresh_users_admin()
            except Exception as e: QMessageBox.critical(self, "Lỗi", f"Không thể thêm user: {e}")
                
    def edit_user_admin(self):
        selected = self.admin_user_list.currentItem()
        if not selected: QMessageBox.warning(self, "Lưu ý", "Hãy chọn một user để sửa."); return
        user_id = selected.data(Qt.UserRole); username = selected.text().split(' ')[0]; is_admin = "(Admin)" in selected.text()
        dialog = UserDialog(self, username=username, is_admin=is_admin)
        if dialog.exec():
            data = dialog.get_data()
            if not data['password']: del data['password']
            try: 
                response = API_SESSION.put(f"{SERVER_URL}/admin/users/{user_id}", json=data)
                response.raise_for_status()
                QMessageBox.information(self, "Kết quả", response.json().get('message')); self.refresh_users_admin()
            except Exception as e: QMessageBox.critical(self, "Lỗi", f"Không thể sửa user: {e}")
                
    def delete_user_admin(self):
        selected = self.admin_user_list.currentItem()
        if not selected: QMessageBox.warning(self, "Lưu ý", "Hãy chọn một user."); return
        user_id = selected.data(Qt.UserRole); username = selected.text().split(' ')[0]
        reply = QMessageBox.question(self, 'Xác nhận', f"Xóa user '{username}'?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            try: 
                response = API_SESSION.delete(f"{SERVER_URL}/admin/users/{user_id}")
                response.raise_for_status()
                QMessageBox.information(self, "Thông báo", response.json().get('message')); self.refresh_users_admin()
            except Exception as e: QMessageBox.critical(self, "Lỗi", f"Không thể xóa: {e}")

# --- Login Window ---
class LoginWindow(QWidget):
    # Lớp này phải nằm trước khối __main__ để tránh NameError
    login_successful = Signal(dict)
    login_failed = Signal(str)

    def __init__(self):
        super().__init__()
        self.setObjectName("LoginWindow")
        self.setWindowTitle("Đăng nhập")
        self.main_window = None
        self.setWindowIcon(QIcon("icon.png"))
        
        settings = QSettings('MyApp', 'ChatClient')
        initial_theme = settings.value('theme', 'dark')
        
        if initial_theme == 'dark': colors = COLORS_DARK
        else: colors = COLORS_LIGHT
            
        stylesheet = get_stylesheet(colors)
        QApplication.instance().colors = colors
        self.setStyleSheet(stylesheet)
        QApplication.instance().setStyleSheet(stylesheet)
        
        self.resize(400, 350)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(40, 40, 40, 40)
        main_layout.addStretch(1)
        
        title = QLabel("Chào Mừng Trở Lại"); title.setObjectName("titleLabel"); title.setAlignment(Qt.AlignCenter)

        self.status_label = QLabel(""); self.status_label.setObjectName("readyLabel"); self.status_label.setAlignment(Qt.AlignCenter)
        
        form_widget = QWidget(); layout = QVBoxLayout(form_widget); layout.setSpacing(15)
        
        self.username_input = QLineEdit(); self.username_input.setPlaceholderText("Tên đăng nhập")
        self.password_input = QLineEdit(); self.password_input.setPlaceholderText("Mật khẩu"); self.password_input.setEchoMode(QLineEdit.Password)
        self.login_button = QPushButton("Đăng nhập")
        
        layout.addWidget(self.username_input); layout.addWidget(self.password_input); layout.addWidget(self.login_button)
        
        main_layout.addWidget(title); main_layout.addWidget(self.status_label); main_layout.addSpacing(15); main_layout.addWidget(form_widget); main_layout.addStretch(2)
        
        self.login_button.clicked.connect(self.start_login_task); self.password_input.returnPressed.connect(self.start_login_task)
        
        self.login_successful.connect(self.show_main_window); self.login_failed.connect(self.handle_login_error)

        self.thread_pool = QThreadPool()
        
        self.server_ready = False
        self.wakeup_task = WakeupTask(); self.wakeup_task.signals.finished.connect(self.handle_wakeup_finished); self.thread_pool.start(self.wakeup_task)
        
        self.login_button.setDisabled(True); self.username_input.setDisabled(True); self.password_input.setDisabled(True)
        self.status_label.setText("") 


    def handle_wakeup_finished(self, success):
        self.server_ready = success
        self.login_button.setDisabled(False); self.username_input.setDisabled(False); self.password_input.setDisabled(False)
        
        if success:
            self.status_label.setText("➤ Vui lòng đăng nhập")
            self.status_label.setStyleSheet(self.styleSheet() + f"QLabel#readyLabel {{ color: {QApplication.instance().colors['accent']}; }}")
        else:
             self.status_label.setText("Lỗi Server. Không thể kết nối ban đầu.")
             self.status_label.setStyleSheet(self.styleSheet() + f"QLabel#readyLabel {{ color: #ff0000; }}")


    def start_login_task(self):
        username, password = self.username_input.text(), self.password_input.text()
        if not username or not password: QMessageBox.warning(self, "Lưu ý", "Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu."); return
        
        if not self.server_ready:
             QMessageBox.warning(self, "Lưu ý", "Server đang khởi động (hoặc lỗi). Vui lòng đợi thông báo sẵn sàng hoặc thử lại sau.");
             return
             
        self.set_ui_loading(True)
        self.status_label.setText("Đang đăng nhập và kết nối...")
        self.status_label.setStyleSheet(self.styleSheet() + f"QLabel#readyLabel {{ color: {QApplication.instance().colors['text_main']}; }}")


        task = LoginTaskRunner(username, password)
        task.signals.finished.connect(self.login_successful.emit); task.signals.error.connect(self.login_failed.emit); self.thread_pool.start(task)

    def show_main_window(self, user_data):
        self.main_window = MainWindow(user_data); self.main_window.show(); self.close()

    def handle_login_error(self, error_message):
        self.set_ui_loading(False); self.status_label.setText("Lỗi đăng nhập!"); QMessageBox.critical(self, "Lỗi", error_message)

    def set_ui_loading(self, loading):
        self.login_button.setDisabled(loading); self.username_input.setDisabled(loading); self.password_input.setDisabled(loading)
        if not loading:
            if self.server_ready:
                self.status_label.setText("➤ Vui lòng đăng nhập")
                self.status_label.setStyleSheet(self.styleSheet() + f"QLabel#readyLabel {{ color: {QApplication.instance().colors['accent']}; }}")
            else:
                 self.status_label.setText("Lỗi Server. Không thể kết nối ban đầu.")


# --- Main Execution Block ---
if __name__ == '__main__':
    QApplication.setApplicationName("ChatClientApp"); QApplication.setOrganizationName("MyApp")

    app = QApplication(sys.argv)
    app.colors = COLORS_DARK
    
    if os.path.exists("icon.png"): app.setWindowIcon(QIcon("icon.png"))
        
    login_win = LoginWindow()
    login_win.show()
    sys.exit(app.exec())
