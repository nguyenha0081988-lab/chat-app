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

# Cấu hình logging cơ bản
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- KHỞI TẠO VÀ CẤU HÌNH ---
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-fallback-secret-key-for-development')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Cấu hình Cloudinary (Yêu cầu biến môi trường CLOUDINARY_*)
CLOUDINARY_FOLDER = "pyside_chat_app"
CLOUDINARY_UPDATE_FOLDER = f"{CLOUDINARY_FOLDER}/updates" 
CLOUDINARY_AVATAR_FOLDER = f"{CLOUDINARY_FOLDER}/avatars" 

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

# --- CÁC ĐƯỜNG DẪN API (ROUTES) ---
@app.route('/update', methods=['GET'])
def check_for_update():
    """Cung cấp phiên bản mới nhất và link tải xuống."""
    try:
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
    except Exception as e:
        logger.error(f"Error accessing /update route: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500


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
        public_id = f"{CLOUDINARY_UPDATE_FOLDER}/client_{version_number}_{uuid.uuid4().hex[:6]}"
        upload_result = cloudinary.uploader.upload(
            update_file, 
            public_id=public_id,
            folder=CLOUDINARY_UPDATE_FOLDER,
            resource_type="auto"
        )
        
        download_url, _ = cloudinary.utils.cloudinary_url(
            upload_result['public_id'], 
            resource_type="raw", 
            attachment=True, 
            flags="download"
        )

        new_version = AppVersion(
            version_number=version_number,
            public_id=upload_result['public_id'],
            download_url=download_url
        )
        db.session.add(new_version)
        db.session.commit()
        
        return jsonify({'message': f'Bản cập nhật v{version_number} đã được tải lên và kích hoạt thành công!', 'url': download_url})
    except Exception as e:
        logger.error(f"Error processing upload-update: {e}")
        return jsonify({'message': f'Lỗi khi tải file cập nhật lên: {e}'}), 500

@app.route('/')
def index(): 
    logger.info("Health check received on /.")
    return "Backend server for the application is running!"

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json(); username, password = data.get('username'), data.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return jsonify({'message': 'Đăng nhập thành công!', 'user_id': user.id, 'username': user.username, 'is_admin': user.is_admin, 'avatar_url': user.avatar_url})
        return jsonify({'message': 'Sai tên đăng nhập hoặc mật khẩu!'}), 401
    except Exception as e:
        logger.error(f"Error during login: {e}")
        return jsonify({'message': 'Lỗi server trong quá trình xử lý đăng nhập.'}), 500


@app.route('/online-users', methods=['GET'])
@login_required
def get_online_users():
    """FIX: Chỉ trả về các user đang online."""
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

@app.route('/history/<int:partner_id>', methods=['DELETE'])
@login_required
def delete_history(partner_id):
    try:
        partner = User.query.get(partner_id)
        if not partner: return jsonify({'message': 'User không tồn tại.'}), 404
        partner_username = partner.username
        db.session.query(Message).filter(or_((Message.sender_id == current_user.id) & (Message.recipient_id == partner_id), (Message.sender_id == partner_id) & (Message.recipient_id == current_user.id))).delete(synchronize_session='fetch')
        db.session.commit()
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
        
        last_sent_read = db.session.query(Message).filter(
            (Message.sender_id == current_user.id) & 
            (Message.recipient_id == partner_id) & 
            (Message.is_read == True)
        ).first()
        
        all_sent_is_read = True if last_sent_read else False

        all_messages = db.session.query(Message).filter(
            or_(
                (Message.sender_id == current_user.id) & (Message.recipient_id == partner_id), 
                (Message.sender_id == partner_id) & (Message.recipient_id == current_user.id)
            )
        ).order_by(Message.timestamp.asc()).all()
        
        history = []
        for msg in all_messages:
            is_mine = msg.sender_id == current_user.id
            msg_is_read = msg.is_read
            
            if is_mine:
                msg_is_read = all_sent_is_read
            
            history.append({
                'id': msg.id, 
                'sender': msg.sender.username, 
                'message': msg.content, 
                'is_read': msg_is_read
            })
        
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
    try:
        data = request.get_json(); public_id = data.get('public_id')
        if not public_id: return jsonify({'message': 'Thiếu ID công khai để xóa file.'}), 400
        file_record = File.query.filter_by(public_id=public_id).first()
        if not file_record: return jsonify({'message': 'File không tồn tại trong CSDL.'}), 404
        if not current_user.is_admin and file_record.user_id != current_user.id: return jsonify({'message': 'Bạn không có quyền xóa file này.'}), 403
        
        cloudinary.uploader.destroy(file_record.public_id, resource_type="raw")
        db.session.delete(file_record); db.session.commit()
        return jsonify({'message': 'File đã được xóa thành công.'})
    except Exception as e: 
        logger.error(f"Error accessing /delete-file: {e}")
        return jsonify({'message': f'Lỗi khi xóa file: {e}'}), 500

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files: return jsonify({'message': 'Không tìm thấy file.'}), 400
    file = request.files['file']
    if file.filename == '': return jsonify({'message': 'Tên file không hợp lệ.'}), 400
    try:
        public_id = f"{CLOUDINARY_FOLDER}/user_files/{uuid.uuid4().hex}"
        upload_result = cloudinary.uploader.upload(file, public_id=public_id, folder=f"{CLOUDINARY_FOLDER}/user_files", resource_type="auto")
        new_file = File(filename=secure_filename(file.filename), public_id=upload_result['public_id'], user_id=current_user.id)
        db.session.add(new_file); db.session.commit()
        return jsonify({'message': f'File {new_file.filename} đã được tải lên thành công!'})
    except Exception as e: 
        logger.error(f"Error accessing /upload: {e}")
        return jsonify({'message': f'Lỗi khi tải file lên: {e}'}), 500

@app.route('/files', methods=['GET'])
@login_required
def get_files():
    """Chỉ trả về các file KHÔNG phải avatar hay bản cập nhật."""
    try:
        files_to_exclude = AppVersion.query.with_entities(AppVersion.public_id).all()
        files_to_exclude_list = [f[0] for f in files_to_exclude]
        
        files = File.query.filter(
            not_(File.public_id.like(f'{CLOUDINARY_AVATAR_FOLDER}/%')), 
            not_(File.public_id.in_(files_to_exclude_list))
        ).all()
        
        file_list = []
        for f in files:
            file_list.append({
                'filename': f.filename, 
                'public_id': f.public_id,
                'uploaded_by': f.owner.username 
            })
            
        return jsonify({'files': file_list})
    except Exception as e:
        logger.error(f"Error accessing /files: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500


@app.route('/download/<string:public_id>', methods=['GET'])
@login_required
def download_file(public_id):
    """FIX: Đảm bảo trả về URL tải xuống thô (raw download URL) trực tiếp từ Cloudinary."""
    try:
        file_record = File.query.filter_by(public_id=public_id).first()
        if not file_record: 
            return jsonify({'message': 'File không tồn tại.'}), 404
        
        # Tạo URL tải xuống thô, không cần qua Flask send_file
        download_url, _ = cloudinary.utils.cloudinary_url(
            file_record.public_id, 
            resource_type="raw", 
            attachment=True, 
            flags="download",
            secure=True
        )
        return jsonify({'download_url': download_url})
    except Exception as e:
        logger.error(f"Error accessing /download/{public_id}: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500


@app.route('/avatars', methods=['GET'])
@login_required
def get_user_avatars():
    try:
        user_files = File.query.filter(File.user_id == current_user.id, File.public_id.like(f'{CLOUDINARY_AVATAR_FOLDER}/%')).all(); avatars = []
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
    if 'avatar' not in request.files: return jsonify({'message': 'Không tìm thấy file ảnh.'}), 400
    avatar = request.files['avatar']
    
    try:
        public_id = f"{CLOUDINARY_AVATAR_FOLDER}/user_{current_user.id}_{uuid.uuid4().hex[:6]}"
        upload_result = cloudinary.uploader.upload(
            avatar, 
            public_id=public_id,
            folder=CLOUDINARY_AVATAR_FOLDER,
            resource_type="image"
        )
        
        new_file = File(
            filename=f"avatar_{uuid.uuid4().hex[:8]}", 
            public_id=upload_result['public_id'],
            user_id=current_user.id
        )
        db.session.add(new_file)
        
        current_user.avatar_url = upload_result['secure_url']
        db.session.commit()
        
        return jsonify({'message': 'Avatar đã được cập nhật!', 'avatar_url': current_user.avatar_url})
    except Exception as e: 
        logger.error(f"Error accessing /avatar/upload: {e}")
        return jsonify({'message': f'Lỗi khi tải lên avatar: {e}'}), 500

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
    except Exception as e: 
        logger.error(f"Error accessing /avatar/select: {e}")
        return jsonify({'message': f'Lỗi khi chọn avatar: {e}'}), 500

@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_get_users():
    try:
        users = User.query.all(); user_list = [{'id': u.id, 'username': u.username, 'is_admin': u.is_admin} for u in users]
        return jsonify({'users': user_list})
    except Exception as e:
        logger.error(f"Error accessing /admin/users GET: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/admin/users', methods=['POST'])
@admin_required
def admin_add_user():
    try:
        data = request.get_json(); username = data.get('username'); password = data.get('password'); is_admin = data.get('is_admin', False)
        if not username or not password: return jsonify({'message': 'Thiếu tên đăng nhập hoặc mật khẩu.'}), 400
        if User.query.filter_by(username=username).first(): return jsonify({'message': 'Tên đăng nhập đã tồn tại.'}), 400
        new_user = User(username=username, is_admin=is_admin); new_user.set_password(password); db.session.add(new_user); db.session.commit()
        return jsonify({'message': f"Người dùng '{username}' đã được tạo."})
    except Exception as e:
        logger.error(f"Error accessing /admin/users POST: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/admin/users/<int:user_id>', methods=['PUT'])
@admin_required
def admin_edit_user(user_id):
    try:
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
    except Exception as e:
        logger.error(f"Error accessing /admin/users PUT: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        if user.id == current_user.id: return jsonify({'message': 'Không thể tự xóa tài khoản của mình.'}), 400
        if user.avatar_url: cloudinary.uploader.destroy(f"{CLOUDINARY_FOLDER}/avatar/{user.id}", resource_type="image")
        db.session.delete(user); db.session.commit()
        if user_id in online_users: del online_users[user_id]
        return jsonify({'message': f"Người dùng '{user.username}' đã bị xóa."})
    except Exception as e:
        logger.error(f"Error accessing /admin/users DELETE: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

# --- CÁC SỰ KIỆN SOCKET.IO ---
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        user_id = current_user.id
        user_data = {'id': user_id, 'username': current_user.username, 'avatar_url': current_user.avatar_url}
        
        # 1. Thêm user vào danh sách online
        online_users[user_id] = request.sid
        logger.info(f"User {current_user.username} connected (SID: {request.sid})")
        
        # 2. Gửi sự kiện cho TẤT CẢ client KHÁC biết có user mới online
        emit('user_connected', user_data, broadcast=True, include_self=False)
        
        # 3. Xử lý thông báo offline và các tin nhắn đã đọc (giữ nguyên logic)
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
        user_id = current_user.id
        username = current_user.username
        if user_id in online_users: 
            del online_users[user_id]
            logger.info(f"User {username} disconnected")
            # Gửi sự kiện cho TẤT CẢ client biết có user ngắt kết nối
            emit('user_disconnected', {'id': user_id, 'username': username}, broadcast=True, include_self=False)


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
