# server.py

import eventlet
eventlet.monkey_patch()

import os
import click
# ... (toàn bộ các dòng import khác giữ nguyên) ...
from flask_socketio import SocketIO, emit

# --- KHỞI TẠO VÀ CẤU HÌNH ---
# ... (toàn bộ phần này giữ nguyên) ...
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
# ... (toàn bộ phần này giữ nguyên) ...
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True); username = db.Column(db.String(80), unique=True, nullable=False); password_hash = db.Column(db.String(256)); is_admin = db.Column(db.Boolean, default=False, nullable=False); files = db.relationship('File', backref='owner', lazy=True, cascade="all, delete-orphan")
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True); filename = db.Column(db.String(255), nullable=False); user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

# --- CÁC ĐƯỜNG DẪN API (ROUTES) ---
# ... (toàn bộ phần này giữ nguyên) ...
@app.route('/')
def index(): return "Backend server for the application is running!"
# --- (Tất cả các API khác như login, files, admin... giữ nguyên) ---

# --- CÁC SỰ KIỆN SOCKET.IO ---
# ... (toàn bộ phần này giữ nguyên) ...

# --- KHỐI LỆNH CHẠY & LỆNH TÙY CHỈNH ---
# SỬA ĐỔI: Tách riêng việc tạo CSDL và tạo Admin mặc định
def init_database(app_context):
    """Initializes the database, creates tables and the default admin."""
    with app_context:
        db.create_all()
        # Kiểm tra xem có user nào chưa
        if User.query.first() is None:
            print("Database is empty. Creating default admin user...")
            # Lấy thông tin từ biến môi trường
            admin_user = os.environ.get('DEFAULT_ADMIN_USER', 'admin')
            admin_pass = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'supersecret') # Mật khẩu mặc định an toàn
            
            if User.query.filter_by(username=admin_user).first() is None:
                default_admin = User(username=admin_user, is_admin=True)
                default_admin.set_password(admin_pass)
                db.session.add(default_admin)
                db.session.commit()
                print(f"Default admin user '{admin_user}' created.")
        else:
            print("Database already contains users.")

# Chạy hàm khởi tạo một lần khi ứng dụng bắt đầu
init_database(app.app_context())

# ... (các lệnh click như make-admin giữ nguyên nếu bạn muốn dùng ở local) ...
@click.command('make-admin')
@click.argument('username')
@with_appcontext
def make_admin(username):
    # ...
    pass
app.cli.add_command(make_admin)


if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
