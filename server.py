import eventlet
eventlet.monkey_patch()

import os, click, cloudinary, cloudinary.uploader, cloudinary.api
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
import uuid

# --- KHỞI TẠO VÀ CẤU HÌNH ---
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-fallback-secret-key-for-development')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Cấu hình Cloudinary (Yêu cầu biến môi trường CLOUDINARY_*)
CLOUDINARY_FOLDER = "pyside_chat_app"

db = SQLAlchemy(app)
login_manager = LoginManager(app)
# Cấu hình SocketIO cho phép mọi nguồn kết nối (cần thiết cho client PySide)
socketio = SocketIO(app, cors_allowed_origins="*")

# Lưu trữ người dùng đang online: {user_id: session_id}
online_users = {}

# Cấu hình Cloudinary
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

@login_manager.user_loader
def load_user(user_id): 
    return User.query.get(int(user_id))

@app.before_request
def create_tables_and_admin():
    with app.app_context():
        # Kiểm tra xem có cần khởi tạo bảng không
        if not inspect(db.engine).has_table('user'):
             db.create_all()
             
        # Tạo admin mặc định nếu chưa có user nào
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

@app.route('/')
def index(): 
    return "Backend server for the application is running!"

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username, password = data.get('username'), data.get('password')
    user = User.query.filter_by(username=username).first()
    
    if user and user.check_password(password):
        login_user(user)
        # Sử dụng 'user_id' cho client để nhất quán với code client đã sửa
        return jsonify({
            'message': 'Đăng nhập thành công!', 
            'user_id': user.id, 
            'username': user.username, 
            'is_admin': user.is_admin, 
            'avatar_url': user.avatar_url
        })
    return jsonify({'message': 'Sai tên đăng nhập hoặc mật khẩu!'}), 401

@app.route('/online-users', methods=['GET'])
@login_required
def get_online_users():
    # Trả về tất cả người dùng (online_users chỉ dùng cho SocketIO)
    users_info = [
        {'id': u.id, 'username': u.username, 'avatar_url': u.avatar_url} 
        for u in User.query.all()
    ]
    return jsonify({'users': users_info})

@app.route('/history/<int:partner_id>', methods=['GET'])
@login_required
def get_history(partner_id):
    # 1. Đánh dấu tất cả tin nhắn từ partner gửi cho current_user là Đã xem
    messages_to_mark_read = db.session.query(Message).filter(
        (Message.sender_id == partner_id) & 
        (Message.recipient_id == current_user.id) & 
        (Message.is_read == False)
    )
    message_ids_to_update = [msg.id for msg in messages_to_mark_read.all()]
    messages_to_mark_read.update({Message.is_read: True})
    db.session.commit()
    
    # 2. Lấy toàn bộ lịch sử chat
    all_messages = db.session.query(Message).filter(
        or_(
            (Message.sender_id == current_user.id) & (Message.recipient_id == partner_id), 
            (Message.sender_id == partner_id) & (Message.recipient_id == current_user.id)
        )
    ).order_by(Message.timestamp.asc()).all()
    
    history = [
        {
            'id': msg.id, 
            'sender': msg.sender.username, 
            'message': msg.content, 
            'is_read': msg.is_read
        } 
        for msg in all_messages
    ]
    
    # 3. Gửi sự kiện 'messages_seen' đến partner nếu họ đang online
    partner_sid = online_users.get(partner_id)
    if partner_sid and message_ids_to_update:
        emit('messages_seen', {'ids': message_ids_to_update}, room=partner_sid, namespace='/')
        
    return jsonify(history)

@app.route('/history/<int:partner_id>', methods=['DELETE'])
@login_required
def delete_history(partner_id):
    # Chỉ xóa tin nhắn của current_user gửi và nhận với partner
    db.session.query(Message).filter(
        or_(
            (Message.sender_id == current_user.id) & (Message.recipient_id == partner_id), 
            (Message.sender_id == partner_id) & (Message.recipient_id == current_user.id)
        )
    ).delete(synchronize_session='fetch')
    db.session.commit()
    return jsonify({'message': f"Đã xóa lịch sử chat với user ID {partner_id}."})


# --- FILE UPLOAD/DOWNLOAD/DELETE ---
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'Không tìm thấy file.'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'Tên file không hợp lệ.'}), 400
    
    try:
        # Tải lên Cloudinary
        upload_result = cloudinary.uploader.upload(
            file, 
            folder=CLOUDINARY_FOLDER,
            resource_type="auto"
        )
        
        # Lưu vào DB
        new_file = File(
            filename=secure_filename(file.filename),
            public_id=upload_result['public_id'],
            user_id=current_user.id
        )
        db.session.add(new_file)
        db.session.commit()
        
        return jsonify({'message': f'File {new_file.filename} đã được tải lên thành công!'})
    except Exception as e:
        print(f"Cloudinary upload error: {e}")
        return jsonify({'message': f'Lỗi khi tải file lên: {e}'}), 500

@app.route('/files', methods=['GET'])
@login_required
def get_files():
    files = File.query.all()
    file_list = [
        {'filename': f.filename, 'public_id': f.public_id} 
        for f in files
    ]
    return jsonify({'files': file_list})

@app.route('/download/<string:public_id>', methods=['GET'])
@login_required
def download_file(public_id):
    file_record = File.query.filter_by(public_id=public_id).first()
    if not file_record:
        return jsonify({'message': 'File không tồn tại.'}), 404
    
    # Tạo URL tải xuống bảo mật từ Cloudinary
    download_url, _ = cloudinary.utils.cloudinary_url(
        file_record.public_id, 
        resource_type="raw", 
        attachment=True, 
        flags="download"
    )
    return jsonify({'download_url': download_url})

# ĐIỂM SỬA CHỮA: Cho phép cả DELETE và POST để tương thích với môi trường hosting
@app.route('/delete/<string:public_id>', methods=['DELETE', 'POST'])
@login_required
def delete_file(public_id=None):
    # Lấy public_id từ URL (DELETE) hoặc từ JSON body (POST fallback)
    # LƯU Ý: Nếu client dùng POST, public_id trong URL có thể là rỗng, ta phải lấy từ JSON
    if public_id is None or not public_id.strip():
        if request.is_json:
            try:
                data = request.get_json()
                public_id = data.get('public_id')
            except:
                pass # Bỏ qua nếu không phải JSON hợp lệ
        
    if not public_id:
        return jsonify({'message': 'Thiếu ID công khai để xóa file.'}), 400
        
    file_record = File.query.filter_by(public_id=public_id).first()
    
    if not file_record:
        # Nếu file không tồn tại, trả về 404
        return jsonify({'message': 'File không tồn tại trong CSDL.'}), 404
        
    # Chỉ Admin hoặc người sở hữu mới được xóa file
    if not current_user.is_admin and file_record.user_id != current_user.id:
        return jsonify({'message': 'Bạn không có quyền xóa file này.'}), 403

    try:
        # Xóa trên Cloudinary
        cloudinary.uploader.destroy(file_record.public_id, resource_type="raw")
        
        # Xóa trong DB
        db.session.delete(file_record)
        db.session.commit()
        
        return jsonify({'message': 'File đã được xóa thành công.'})
    except Exception as e:
        return jsonify({'message': f'Lỗi khi xóa file: {e}'}), 500

# --- AVATAR UPLOAD ---
@app.route('/avatar/upload', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        return jsonify({'message': 'Không tìm thấy file ảnh.'}), 400
    avatar = request.files['avatar']
    
    try:
        # Tải lên Cloudinary, ghi đè ảnh cũ (dùng user ID làm public ID)
        public_id = f"{CLOUDINARY_FOLDER}/avatar/{current_user.id}"
        upload_result = cloudinary.uploader.upload(
            avatar, 
            public_id=public_id,
            overwrite=True,
            folder=CLOUDINARY_FOLDER,
            resource_type="image"
        )
        
        # Cập nhật URL trong DB
        current_user.avatar_url = upload_result['secure_url']
        db.session.commit()
        
        return jsonify({
            'message': 'Avatar đã được cập nhật!', 
            'avatar_url': current_user.avatar_url
        })
    except Exception as e:
        return jsonify({'message': f'Lỗi khi tải lên avatar: {e}'}), 500

# --- ADMIN ROUTES ---
@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_get_users():
    users = User.query.all()
    user_list = [
        {'id': u.id, 'username': u.username, 'is_admin': u.is_admin} 
        for u in users
    ]
    return jsonify({'users': user_list})

@app.route('/admin/users', methods=['POST'])
@admin_required
def admin_add_user():
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
    return jsonify({'message': f"Người dùng '{username}' đã được tạo."})

@app.route('/admin/users/<int:user_id>', methods=['PUT'])
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    
    # Cập nhật username
    new_username = data.get('username')
    if new_username and new_username != user.username:
        if User.query.filter_by(username=new_username).first():
            return jsonify({'message': 'Tên đăng nhập mới đã tồn tại.'}), 400
        user.username = new_username

    # Cập nhật password
    new_password = data.get('password')
    if new_password:
        user.set_password(new_password)

    # Cập nhật admin status
    is_admin = data.get('is_admin')
    if is_admin is not None:
        user.is_admin = is_admin

    db.session.commit()
    return jsonify({'message': f"Thông tin người dùng ID {user_id} đã được cập nhật."})

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        return jsonify({'message': 'Không thể tự xóa tài khoản của mình.'}), 400
    
    # Xóa file avatar nếu có
    if user.avatar_url:
         public_id = f"{CLOUDINARY_FOLDER}/avatar/{user.id}"
         cloudinary.uploader.destroy(public_id, resource_type="image")
         
    # Xóa user (sqlalchemy cascade sẽ tự động xóa files và messages)
    db.session.delete(user)
    db.session.commit()
    
    # Xóa khỏi danh sách online nếu đang online
    if user_id in online_users:
        del online_users[user_id]
        
    return jsonify({'message': f"Người dùng '{user.username}' đã bị xóa."})

# --- CÁC SỰ KIỆN SOCKET.IO ---

@socketio.on('connect')
def handle_connect():
    # Kiểm tra xem người dùng đã đăng nhập chưa
    if current_user.is_authenticated:
        online_users[current_user.id] = request.sid
        print(f"User {current_user.username} connected (SID: {request.sid})")
        
        # 1. Gửi thông báo tin nhắn chưa đọc (offline_notifications)
        # Tìm các tin nhắn chưa đọc gửi đến user hiện tại
        unread_messages = (db.session.query(Message.sender_id)
                          .filter(Message.recipient_id == current_user.id, Message.is_read == False)
                          .group_by(Message.sender_id)
                          .all())
                          
        # Đếm số lượng tin nhắn chưa đọc theo từng người gửi
        counts_dict = {}
        for sender_id, in unread_messages:
            sender = User.query.get(sender_id)
            if sender:
                # Tìm tổng số tin nhắn chưa đọc từ người gửi này
                count = Message.query.filter_by(sender_id=sender_id, recipient_id=current_user.id, is_read=False).count()
                counts_dict[sender.username] = count

        if counts_dict:
            emit('offline_notifications', {'counts': counts_dict}, room=request.sid)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        # Xóa khỏi danh sách online khi ngắt kết nối
        if current_user.id in online_users:
            del online_users[current_user.id]
            print(f"User {current_user.username} disconnected")

@socketio.on('private_message')
@login_required
def handle_private_message(data):
    recipient_id = data.get('recipient_id')
    content = data.get('message')
    
    if not recipient_id or not content:
        return # Bỏ qua tin nhắn không hợp lệ

    # 1. Lưu tin nhắn vào DB
    new_msg = Message(
        sender_id=current_user.id, 
        recipient_id=recipient_id, 
        content=content
    )
    db.session.add(new_msg)
    db.session.commit()

    # 2. Chuẩn bị dữ liệu để gửi đi
    msg_data = {
        'id': new_msg.id,
        'sender': current_user.username,
        'message': content,
        'is_read': False 
    }
    
    # 3. Gửi đến người nhận (nếu online)
    recipient_sid = online_users.get(recipient_id)
    if recipient_sid:
        # Gửi đến phòng của người nhận
        emit('message_from_server', msg_data, room=recipient_sid)
    
    # 4. Gửi ngược lại cho người gửi (để hiển thị tin nhắn vừa gửi)
    # Dùng request.sid để đảm bảo gửi về đúng client hiện tại
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
    # Lưu ý: Sử dụng eventlet là cần thiết khi dùng Flask-SocketIO
    socketio.run(app, debug=True, port=5000)
