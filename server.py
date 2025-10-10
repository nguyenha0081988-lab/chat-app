import eventlet
eventlet.monkey_patch() # BẮT BUỘC Ở DÒNG ĐẦU TIÊN

import os
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, not_, text
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from functools import wraps
from flask_socketio import SocketIO, emit
import uuid
import logging
import urllib.parse
from dateutil import parser as dateparser
from sqlalchemy.exc import OperationalError

# Cấu hình logging cơ bản
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- KHỞI TẠO VÀ CẤU HÌNH GLOBAL ---
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

# --- DECORATOR, MODELS, USER_LOADER, UTILS ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({'message': 'Yêu cầu quyền Admin!'}), 403
        return f(*args, **kwargs)
    return decorated_function
    
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

    last_opened_by = db.Column(db.String(80), nullable=True)
    last_opened_at = db.Column(db.DateTime, nullable=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    
    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(512), nullable=False)
    is_admin_action = db.Column(db.Boolean, default=False)

class AppVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version_number = db.Column(db.String(50), nullable=False, unique=True)
    public_id = db.Column(db.String(255), nullable=False)
    download_url = db.Column(db.String(512), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def apply_schema_fixes_manually(db):
    """Thêm các cột mới (last_opened) nếu chúng chưa tồn tại, giữ lại dữ liệu."""
    with db.engine.connect() as connection:
        # Kiểm tra và thêm cột last_opened_by
        try:
            # Dùng VARCHAR cho cả SQLite và Postgres (VARCHAR là tương thích rộng)
            connection.execute(text("ALTER TABLE file ADD COLUMN last_opened_by VARCHAR(80)"))
            print("Successfully added column 'last_opened_by' via raw SQL.")
        except OperationalError:
            print("Column 'last_opened_by' already exists or failed to add.")
        
        # Kiểm tra và thêm cột last_opened_at
        try:
            # Dùng DATETIME cho cả SQLite và Postgres
            connection.execute(text("ALTER TABLE file ADD COLUMN last_opened_at DATETIME"))
            print("Successfully added column 'last_opened_at' via raw SQL.")
        except OperationalError:
            print("Column 'last_opened_at' already exists or failed to add.")
        
        connection.commit()


# --- KHỐI KHỞI TẠO ỨNG DỤNG (Chỉ chạy một lần khi app được tải) ---
with app.app_context():
    # 1. TẠO TẤT CẢ CÁC BẢNG NẾU CHƯA TỒN TẠI (Đảm bảo bảng 'log' được tạo)
    db.create_all()
    
    # 2. ÁP DỤNG CÁC SỬA CHỮA THỦ CÔNG (THÊM CỘT BẰNG SQL THÔ)
    try:
        apply_schema_fixes_manually(db)
    except Exception as e:
        logger.error(f"FATAL: Failed to apply manual SQL fixes: {e}")

    # 3. KIỂM TRA VÀ TẠO ADMIN MẶC ĐỊNH
    if User.query.first() is None:
        try:
            admin_user = os.environ.get('DEFAULT_ADMIN_USER', 'admin')
            admin_pass = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'adminpass')
            
            if admin_pass and User.query.filter_by(username=admin_user).first() is None:
                default_admin = User(username=admin_user, is_admin=True)
                default_admin.set_password(admin_pass)
                db.session.add(default_admin)
                db.session.commit()
                logger.info(f"Default admin user '{admin_user}' created.")
                log_action(admin_user, "Initial admin account created by system.", is_admin=True)
        except Exception as e:
            logger.error(f"Error during initial admin creation: {e}")
            
# ------------------------------------------------------------------------

# --- CÁC ĐƯỜNG DẪN API (ROUTES) ---
@app.route('/update', methods=['GET'])
def check_for_update():
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
            folder=None,
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
        
        log_action(current_user.username, f"Uploaded and activated client update v{version_number}.", is_admin=True)
        
        return jsonify({'message': f'Bản cập nhật v{version_number} đã được tải lên và kích hoạt thành công!', 'url': download_url})
    except Exception as e:
        logger.error(f"Error processing upload-update: {e}")
        return jsonify({'message': 'Lỗi khi tải file cập nhật lên: {}'.format(e)}), 500

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
            log_action(user.username, "Logged in successfully.")
            return jsonify({
                'message': 'Đăng nhập thành công!',
                'user_id': user.id,
                'username': user.username,
                'is_admin': user.is_admin,
                'avatar_url': user.avatar_url
            })
        log_action(username, "Failed login attempt.", is_admin=False)
        return jsonify({'message': 'Sai tên đăng nhập hoặc mật khẩu!'}), 401
    except Exception as e:
        logger.error(f"Error during login: {e}")
        return jsonify({'message': 'Lỗi server trong quá trình xử lý đăng nhập.'}), 500

@app.route('/online-users', methods=['GET'])
@login_required
def get_online_users():
    try:
        online_user_ids = list(online_users.keys())
        users = User.query.filter(User.id.in_(online_user_ids)).all()

        users_info = []
        for u in users:
            if u.id != current_user.id:
                users_info.append({
                    'id': u.id,
                    'username': u.username,
                    'avatar_url': u.avatar_url
                })
        
        return jsonify({'users': users_info})
    except Exception as e:
        logger.error(f"Error accessing /online-users: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/history/<int:partner_id>', methods=['DELETE'])
@login_required
def delete_history(partner_id):
    try:
        partner = User.query.get(partner_id)
        if not partner:
            return jsonify({'message': 'User không tồn tại.'}), 404
        
        partner_username = partner.username
        db.session.query(Message).filter(
            or_(
                (Message.sender_id == current_user.id) & (Message.recipient_id == partner_id),
                (Message.sender_id == partner_id) & (Message.recipient_id == current_user.id)
            )
        ).delete(synchronize_session='fetch')
        db.session.commit()
        
        return jsonify({'message': f"Đã xóa lịch sử chat với user {partner_username}."})
    except Exception as e:
        logger.error(f"Error accessing /history DELETE: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/history/<int:partner_id>', methods=['GET'])
@login_required
def get_history(partner_id):
    try:
        messages_to_mark_read = db.session.query(Message).filter(
            (Message.sender_id == partner_id) &
            (Message.recipient_id == current_user.id) &
            (Message.is_read == False)
        )
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
        
        log_action(current_user.username, f"Deleted file: {file_record.filename} (ID: {file_record.public_id})", is_admin=current_user.is_admin)
        
        return jsonify({'message': 'File đã được xóa thành công.'})
    except Exception as e:
        logger.error(f"Error accessing /delete-file: {e}")
        return jsonify({'message': 'Lỗi khi xóa file: {}'.format(e)}), 500

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'Không tìm thấy file.'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'Tên file không hợp lệ.'}), 400
    
    original_filename = file.filename
    
    try:
        file_base_name, file_extension = os.path.splitext(original_filename)
        safe_filename_part = secure_filename(file_base_name)
        
        public_id_part = f"{safe_filename_part}_{uuid.uuid4().hex[:6]}{file_extension}"
        public_id_base = f"{CLOUDINARY_USER_FILES_FOLDER}/{public_id_part}"
        
        upload_result = cloudinary.uploader.upload(
            file,
            public_id=public_id_base,
            resource_type="auto"
        )
        
        resource_type_from_cloudinary = upload_result.get('resource_type', 'raw')
        
        new_file = File(
            filename=original_filename,
            public_id=upload_result['public_id'],
            resource_type=resource_type_from_cloudinary,
            user_id=current_user.id
        )
        db.session.add(new_file)
        db.session.commit()
        
        log_action(current_user.username, f"Uploaded new file: {new_file.filename} (ID: {new_file.public_id})", is_admin=current_user.is_admin)
        
        return jsonify({'message': f'File {new_file.filename} đã được tải lên thành công!'})
    except Exception as e:
        logger.error(f"Error accessing /upload: {e}")
        return jsonify({'message': 'Lỗi khi tải file lên: {}'.format(e)}), 500

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
                'last_opened_by': f.last_opened_by,
                'last_opened_at': f.last_opened_at.isoformat() if f.last_opened_at else None
            })
            
        return jsonify({'files': file_list})
    except Exception as e:
        logger.error(f"Error accessing /files: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

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
        
        download_url, _ = cloudinary.utils.cloudinary_url(
            file_record.public_id,
            resource_type=file_record.resource_type,
            type="upload",
            attachment=True,
            flags="attachment",
            secure=True
        )
        
        logger.info(f"[DOWNLOAD] URL tạo thành công: {download_url[:100]}...")
        
        return jsonify({'download_url': download_url})
        
    except Exception as e:
        logger.error(f"Error in /download: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500


@app.route('/avatars', methods=['GET'])
@login_required
def get_user_avatars():
    try:
        user_files = File.query.filter(
            File.user_id == current_user.id,
            File.public_id.like(f'{CLOUDINARY_AVATAR_FOLDER}/%')
        ).all()
        
        avatars = []
        for f in user_files:
            avatar_url, _ = cloudinary.utils.cloudinary_url(
                f.public_id,
                resource_type="image",
                width=100,
                height=100,
                crop="fill"
            )
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
        upload_result = cloudinary.uploader.upload(
            avatar,
            public_id=public_id,
            folder=None,
            resource_type="image"
        )
        
        new_file = File(
            filename=f"avatar_{uuid.uuid4().hex[:8]}",
            public_id=upload_result['public_id'],
            resource_type='image',
            user_id=current_user.id
        )
        db.session.add(new_file)
        
        current_user.avatar_url = upload_result['secure_url']
        db.session.commit()
        
        return jsonify({
            'message': 'Avatar đã được cập nhật!',
            'avatar_url': current_user.avatar_url
        })
    except Exception as e:
        logger.error(f"Error accessing /avatar/upload: {e}")
        return jsonify({'message': 'Lỗi khi tải lên avatar: {}'.format(e)}), 500

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
        new_avatar_url, _ = cloudinary.utils.cloudinary_url(
            file_record.public_id,
            resource_type="image",
            version=datetime.now().timestamp()
        )
        current_user.avatar_url = new_avatar_url
        db.session.commit()
        
        return jsonify({
            'message': 'Avatar đã được cập nhật!',
            'avatar_url': current_user.avatar_url
        })
    except Exception as e:
        logger.error(f"Error accessing /avatar/select: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_get_users():
    try:
        users = User.query.all()
        user_list = [
            {'id': u.id, 'username': u.username, 'is_admin': u.is_admin}
            for u in users
        ]
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
        
        log_action(current_user.username, f"Created new user: {username} (Admin: {is_admin})", is_admin=True)
        
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
        
        new_username = data.get('username')
        if new_username and new_username != user.username:
            if User.query.filter_by(username=new_username).first():
                return jsonify({'message': 'Tên đăng nhập mới đã tồn tại.'}), 400
            user.username = new_username
        
        new_password = data.get('password')
        if new_password:
            user.set_password(new_password)
        
        is_admin = data.get('is_admin')
        if is_admin is not None:
            user.is_admin = is_admin
        
        db.session.commit()
        
        log_action(current_user.username, f"Edited user ID {user_id} ({user.username}). Details: Pass Changed: {'Yes' if new_password else 'No'}, IsAdmin: {is_admin}", is_admin=True)
        
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
        
        if user.avatar_url:
            cloudinary.uploader.destroy(
                f"{CLOUDINARY_ROOT_FOLDER}/avatar/{user.id}",
                resource_type="image"
            )
        
        db.session.delete(user)
        db.session.commit()
        
        log_action(current_user.username, f"Deleted user ID {user_id}: {user.username}", is_admin=True)
        
        if user_id in online_users:
            del online_users[user_id]
        
        return jsonify({'message': f"Người dùng '{user.username}' đã bị xóa."})
    except Exception as e:
        logger.error(f"Error accessing /admin/users DELETE: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/admin/logs', methods=['GET'])
@admin_required
def admin_get_logs():
    try:
        logs = Log.query.order_by(Log.timestamp.desc()).limit(500).all()
        
        log_list = []
        for log in logs:
            log_list.append({
                'timestamp': log.timestamp.isoformat(),
                'username': log.username,
                'action': log.action
            })
            
        return jsonify({'logs': log_list[::-1]})
    except Exception as e:
        logger.error(f"Error accessing /admin/logs GET: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500


# --- CÁC SỰ KIỆN SOCKET.IO ---
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        user_id = current_user.id
        user_data = {
            'id': user_id,
            'username': current_user.username,
            'avatar_url': current_user.avatar_url
        }
        
        online_users[user_id] = request.sid
        logger.info(f"User {current_user.username} connected (SID: {request.sid})")
        
        emit('user_connected', user_data, broadcast=True, include_self=False)
        
        unread_messages = (
            db.session.query(Message.sender_id)
            .filter(Message.recipient_id == current_user.id, Message.is_read == False)
            .group_by(Message.sender_id)
            .all()
        )
        
        counts_dict = {}
        for sender_id, in unread_messages:
            sender = User.query.get(sender_id)
            if sender:
                count = Message.query.filter_by(
                    sender_id=sender_id,
                    recipient_id=current_user.id,
                    is_read=False
                ).count()
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
    
    msg_data = {
        'id': new_msg.id,
        'sender': current_user.username,
        'message': content,
        'is_read': False
    }
    
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
