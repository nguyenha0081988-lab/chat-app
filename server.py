# server.py

# Tối ưu cho eventlet: Các dòng này PHẢI nằm ở trên cùng
import eventlet
eventlet.monkey_patch()

# Các thư viện khác
import os
import click
import cloudinary
import cloudinary.uploader
import cloudinary.api
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

# --- KHỞI TẠO VÀ CẤU HÌNH ---
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-fallback-secret-key-for-development')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")
online_users = {} # key: user_id, value: session_id

# Cấu hình Cloudinary
cloudinary.config(
    cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME'),
    api_key=os.environ.get('CLOUDINARY_API_KEY'),
    api_secret=os.environ.get('CLOUDINARY_API_SECRET'),
    secure=True
)

# --- DECORATOR KIỂM TRA ADMIN ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({'message': 'Yêu cầu quyền Admin!'}), 403
        return f(*args, **kwargs)
    return decorated_function

# --- CÁC MODEL CƠ SỞ DỮ LIỆU ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    avatar_url = db.Column(db.String(256), nullable=True)
    files = db.relationship('File', backref='owner', lazy=True, cascade="all, delete-orphan")
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender_user', lazy=True, cascade="all, delete-orphan")
    received_messages = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient_user', lazy=True, cascade="all, delete-orphan")
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

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

@app.before_request
def create_tables_and_admin():
    with app.app_context():
        db.create_all()
        if User.query.first() is None:
            admin_user = os.environ.get('DEFAULT_ADMIN_USER', 'admin')
            admin_pass = os.environ.get('DEFAULT_ADMIN_PASSWORD')
            if admin_pass and User.query.filter_by(username=admin_user).first() is None:
                default_admin = User(username=admin_user, is_admin=True)
                default_admin.set_password(admin_pass)
                db.session.add(default_admin)
                db.session.commit()
                print(f"Default admin user '{admin_user}' created.")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
    users_info = [{'id': u.id, 'username': u.username, 'avatar_url': u.avatar_url} for u in User.query.all()]
    return jsonify({'users': users_info})

@app.route('/avatar/upload', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        return jsonify({'message': 'Không tìm thấy file avatar'}), 400
    file_to_upload = request.files['avatar']
    try:
        upload_result = cloudinary.uploader.upload(
            file_to_upload,
            public_id=f"avatars/{current_user.id}",
            overwrite=True,
            transformation=[
                {'width': 100, 'height': 100, 'gravity': "face", 'crop': "thumb"},
                {'radius': "max"}
            ]
        )
        avatar_url = upload_result.get('secure_url')
        current_user.avatar_url = avatar_url
        db.session.commit()
        return jsonify({'message': 'Cập nhật avatar thành công!', 'avatar_url': avatar_url})
    except Exception as e:
        return jsonify({'message': f'Lỗi khi tải avatar: {str(e)}'}), 500

@app.route('/history/<int:partner_id>', methods=['GET'])
@login_required
def get_history(partner_id):
    messages_to_mark_read = db.session.query(Message).filter(
        (Message.sender_id == partner_id) & (Message.recipient_id == current_user.id) & (Message.is_read == False)
    )
    messages_to_mark_read.update({Message.is_read: True})
    db.session.commit()

    all_messages = db.session.query(Message).filter(
        or_((Message.sender_id == current_user.id) & (Message.recipient_id == partner_id), (Message.sender_id == partner_id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()

    history = [{'id': msg.id, 'sender': msg.sender.username if msg.sender else "N/A", 'message': msg.content, 'is_read': msg.is_read} for msg in all_messages]
    
    partner_sid = online_users.get(partner_id)
    if partner_sid:
        message_ids = [msg.id for msg in all_messages if msg.sender_id == partner_id]
        emit('messages_seen', {'ids': message_ids}, room=partner_sid)

    return jsonify(history)


@app.route('/history/<int:partner_id>', methods=['DELETE'])
@login_required
def delete_history(partner_id):
    messages_to_delete = db.session.query(Message).filter(
        or_(
            (Message.sender_id == current_user.id) & (Message.recipient_id == partner_id),
            (Message.sender_id == partner_id) & (Message.recipient_id == current_user.id)
        )
    )
    messages_to_delete.delete(synchronize_session=False)
    db.session.commit()
    return jsonify({'message': 'Lịch sử trò chuyện đã được xóa.'})

@app.route('/files', methods=['GET'])
@login_required
def list_files():
    files = File.query.all()
    return jsonify({'files': [{'filename': f.filename, 'public_id': f.public_id} for f in files]})

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'Không tìm thấy file'}), 400
    file_to_upload = request.files['file']
    if file_to_upload.filename == '':
        return jsonify({'message': 'Chưa chọn file nào'}), 400
    try:
        upload_result = cloudinary.uploader.upload(file_to_upload, resource_type="raw")
        new_file = File(filename=file_to_upload.filename, public_id=upload_result['public_id'], owner=current_user)
        db.session.add(new_file)
        db.session.commit()
        return jsonify({'message': 'Tải file lên thành công!'}), 201
    except Exception as e:
        return jsonify({'message': f'Lỗi khi tải file lên: {e}'}), 500

@app.route('/download/<public_id>', methods=['GET'])
@login_required
def download_file(public_id):
    try:
        download_url = cloudinary.utils.cloudinary_url(public_id, resource_type="raw", attachment=True)[0]
        return jsonify({'download_url': download_url})
    except Exception as e:
        return jsonify({'message': f'Không tìm thấy file: {e}'}), 404

@app.route('/delete/<public_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_file(public_id):
    file_record = File.query.filter_by(public_id=public_id).first()
    if not file_record:
        return jsonify({'message': 'File không tồn tại'}), 404
    try:
        cloudinary.uploader.destroy(public_id, resource_type="raw")
        db.session.delete(file_record)
        db.session.commit()
        return jsonify({'message': f"File '{file_record.filename}' đã được xóa"})
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Lỗi khi xóa file: {e}'}), 500

@app.route('/admin/users', methods=['GET'])
@login_required
@admin_required
def get_all_users():
    users = User.query.all()
    user_list = [{'id': u.id, 'username': u.username, 'is_admin': u.is_admin} for u in users]
    return jsonify({'users': user_list})

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
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.username == current_user.username:
        return jsonify({'message': 'Không thể tự xóa chính mình'}), 403
    db.session.delete(user_to_delete)
    db.session.commit()
    return jsonify({'message': f'User {user_to_delete.username} đã bị xóa.'})

# --- CÁC SỰ KIỆN SOCKET.IO ---
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        online_users[current_user.id] = request.sid
        unread_messages = db.session.query(Message.sender_id, db.func.count(Message.id)).filter(
            Message.recipient_id == current_user.id,
            Message.is_read == False
        ).group_by(Message.sender_id).all()
        if unread_messages:
            unread_counts = {User.query.get(sender_id).username: count for sender_id, count in unread_messages}
            emit('offline_notifications', {'counts': unread_counts}, room=request.sid)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated and current_user.id in online_users:
        del online_users[current_user.id]

@socketio.on('private_message')
def handle_private_message(data):
    recipient_id = data['recipient_id']
    message_content = data['message']
    new_message = Message(sender_id=current_user.id, recipient_id=recipient_id, content=message_content)
    db.session.add(new_message)
    db.session.commit()

    payload = {'id': new_message.id, 'sender': current_user.username, 'message': message_content}
    
    recipient_sid = online_users.get(recipient_id)
    sender_sid = online_users.get(current_user.id)
    
    if recipient_sid:
        emit('message_from_server', payload, room=recipient_sid)
        if sender_sid:
            emit('message_status_update', {'id': new_message.id, 'status': 'Đã nhận'}, room=sender_sid)
    
    if sender_sid:
        emit('message_from_server', payload, room=sender_sid)

@socketio.on('start_typing')
def handle_start_typing(data):
    recipient_sid = online_users.get(data['recipient_id'])
    if recipient_sid:
        emit('user_is_typing', {'username': current_user.username}, room=recipient_sid)

@socketio.on('stop_typing')
def handle_stop_typing(data):
    recipient_sid = online_users.get(data['recipient_id'])
    if recipient_sid:
        emit('user_stopped_typing', {'username': current_user.username}, room=recipient_sid)

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
