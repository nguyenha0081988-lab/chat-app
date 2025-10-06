# client.py

import sys, os, requests
from PySide6.QtWidgets import (QApplication, QWidget, QLabel, QLineEdit, 
                               QPushButton, QVBoxLayout, QMessageBox, QMainWindow,
                               QListWidget, QFileDialog, QHBoxLayout, QTextEdit,
                               QSplitter, QListWidgetItem)
from PySide6.QtCore import Qt
import socketio

# --- Cài đặt chung ---
api_session = requests.Session()
SERVER_URL = 'http://ngothepy.pythonanywhere.com'
sio = socketio.Client(http_session=api_session)

# --- Cửa sổ chính của ứng dụng ---
class MainWindow(QMainWindow):
    def __init__(self, user_info):
        super().__init__()
        self.user_info = user_info
        username = user_info['username']
        self.setWindowTitle(f"Ứng Dụng Chat - Chào mừng {username}")
        self.resize(1000, 700)
        self.current_chat_partner = None

        # --- Giao diện ---
        main_widget = QWidget()
        main_layout = QHBoxLayout(main_widget)
        splitter = QSplitter(Qt.Horizontal)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        self.online_users_list = QListWidget()
        # Nút quản lý file có thể thêm ở đây nếu muốn
        left_layout.addWidget(QLabel("Người Dùng Online:"))
        left_layout.addWidget(self.online_users_list)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)
        self.message_input = QLineEdit()
        self.send_button = QPushButton("Gửi")
        chat_input_layout = QHBoxLayout()
        chat_input_layout.addWidget(self.message_input)
        chat_input_layout.addWidget(self.send_button)
        right_layout.addWidget(self.chat_history)
        right_layout.addLayout(chat_input_layout)

        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([250, 750])
        main_layout.addWidget(splitter)
        self.setCentralWidget(main_widget)

        # --- Kết nối sự kiện ---
        self.send_button.clicked.connect(self.send_message)
        self.online_users_list.currentItemChanged.connect(self.select_chat_partner)
        
        # --- Kết nối Socket.IO ---
        self.setup_socketio_events()
        try:
            sio.connect(SERVER_URL)
        except socketio.exceptions.ConnectionError as e:
            QMessageBox.critical(self, "Lỗi Kết Nối", f"Không thể kết nối đến chat server: {e}")

    def select_chat_partner(self, current, previous):
        if current:
            self.current_chat_partner = {'id': current.data(Qt.UserRole), 'username': current.text()}
            self.chat_history.clear()
            self.chat_history.append(f"--- Bắt đầu chat với {self.current_chat_partner['username']} ---")
            
    def setup_socketio_events(self):
        @sio.on('connect')
        def on_connect():
            print("Connected to server!")

        @sio.on('user_status_changed')
        def on_user_status_changed(data):
            self.update_online_users(data['users'])

        @sio.on('message_from_server')
        def on_message(data):
            self.chat_history.append(f"<b>{data['sender']}</b>: {data['message']}")

    def update_online_users(self, users):
        self.online_users_list.clear()
        for user in users:
            if user['id'] != self.user_info['user_id']:
                item = QListWidgetItem(user['username'])
                item.setData(Qt.UserRole, user['id'])
                self.online_users_list.addItem(item)
    
    def send_message(self):
        message = self.message_input.text()
        if message and self.current_chat_partner:
            sio.emit('private_message', {'recipient_id': self.current_chat_partner['id'], 'message': message})
            self.message_input.clear()

    def closeEvent(self, event):
        if sio.connected:
            sio.disconnect()
        event.accept()

# --- Cửa sổ Đăng nhập / Đăng ký ---
class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Đăng nhập / Đăng ký")
        self.main_window = None
        # ... (Toàn bộ code giao diện giữ nguyên)
        layout=QVBoxLayout();self.username_label=QLabel("Tên đăng nhập");self.username_input=QLineEdit();self.password_label=QLabel("Mật khẩu");self.password_input=QLineEdit();self.password_input.setEchoMode(QLineEdit.Password);self.login_button=QPushButton("Đăng nhập");self.register_button=QPushButton("Đăng ký");layout.addWidget(self.username_label);layout.addWidget(self.username_input);layout.addWidget(self.password_label);layout.addWidget(self.password_input);layout.addWidget(self.login_button);layout.addWidget(self.register_button);self.setLayout(layout);self.login_button.clicked.connect(self.login);self.register_button.clicked.connect(self.register)

    def login(self):
        username, password = self.username_input.text(), self.password_input.text()
        try:
            response = api_session.post(f'{SERVER_URL}/login', json={'username': username, 'password': password})
            data = response.json()
            if response.status_code == 200:
                self.main_window = MainWindow(data)
                self.main_window.show()
                self.close()
            else:
                QMessageBox.warning(self, "Thất bại", data.get('message'))
        except (requests.ConnectionError, requests.exceptions.JSONDecodeError):
            QMessageBox.critical(self, "Lỗi", "Không thể kết nối hoặc nhận phản hồi từ server.")

    def register(self):
        username, password = self.username_input.text(), self.password_input.text()
        try:
            response = api_session.post(f'{SERVER_URL}/register', json={'username': username, 'password': password})
            QMessageBox.information(self, "Thông báo", response.json().get('message'))
        except (requests.ConnectionError, requests.exceptions.JSONDecodeError):
            QMessageBox.critical(self, "Lỗi", "Không thể kết nối hoặc nhận phản hồi từ server.")

# --- KHỐI LỆNH CHẠY CHÍNH ---
if __name__ == '__main__':
    app = QApplication(sys.argv)
    login_win = LoginWindow()
    login_win.show()
    sys.exit(app.exec())