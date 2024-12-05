#!/usr/bin/env python3
import sys
import os
import shutil
import zipfile
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QPushButton, 
                             QLabel, QLineEdit, QMessageBox, QFileDialog, 
                             QCheckBox, QComboBox)
from PyQt5.QtCore import Qt, QSettings
from PyQt5.QtGui import QColor, QPalette, QIcon, QPixmap, QFont
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

def get_logo_path():
    """Logo dosyasının yolunu döndürür."""
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, "folenlo.png")
    elif os.path.exists("/usr/share/icons/hicolor/48x48/apps/folenlo.png"):
        return "/usr/share/icons/hicolor/48x48/apps/folenlo.png"
    elif os.path.exists("folenlo.png"):
        return "folenlo.png"
    return None

def get_icon_path():
    """Simge dosyasının yolunu döndürür."""
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, "folenlo.png")
    elif os.path.exists("/usr/share/icons/hicolor/48x48/apps/folenlo.png"):
        return "/usr/share/icons/hicolor/48x48/apps/folenlo.png"
    return None

LOGO_PATH = get_logo_path()
ICON_PATH = get_icon_path()

class FolderEncryptorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.settings = QSettings('FOLEN', 'FolderEncryptor')
        self.initUI()
        self.setup_language()

    def initUI(self):
        self.setWindowTitle('FOLEN | Folder Encryptation')
        self.setFixedSize(350, 450)

        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(53, 53, 53))
        palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
        palette.setColor(QPalette.Base, QColor(25, 25, 25))
        palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
        palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))
        palette.setColor(QPalette.Text, QColor(255, 255, 255))
        palette.setColor(QPalette.Button, QColor(53, 53, 53))
        palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        self.setPalette(palette)
        
        layout = QVBoxLayout()

        self.language_combo = QComboBox()
        self.language_combo.addItems(['Türkçe', 'English'])
        self.language_combo.currentIndexChanged.connect(self.change_language)

        self.language_combo.setStyleSheet("""
            QComboBox {
                background-color: #353535;
                color: white;
                border: 1px solid gray;
                padding: 5px;
            }
            QComboBox::drop-down {
                background-color: #353535;
                border-left: 1px solid gray;
            }
            QComboBox QAbstractItemView {
                background-color: #353535;
                selection-background-color: #454545;
                color: white;
            }
        """)
        layout.addWidget(self.language_combo)

   
        if LOGO_PATH:
            self.logo_label = QLabel(self)  # Logo için QLabel oluştur
            pixmap = QPixmap(LOGO_PATH)
            scaled_pixmap = pixmap.scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.logo_label.setPixmap(scaled_pixmap)  # Logo resmini set et
            self.logo_label.setAlignment(Qt.AlignCenter)
            layout.addWidget(self.logo_label)  # Logo'yu layout'a ekle

        self.label = QLabel('Lütfen bir klasör veya FOLEN dosyası seçmek için tıklayın veya sürükleyip bırakın.')
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setWordWrap(True)
        layout.addWidget(self.label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText('Parola (4-32 karakter)')
        self.password_input.setVisible(False)

        self.password_input.setStyleSheet("""
            QLineEdit {
                background-color: #353535;
                color: white;
                border: 1px solid gray;
                padding: 8px;
                border-radius: 5px;
                font-size: 12px;
            }
            QLineEdit:focus {
                border: 1px solid #4A90E2;
            }
        """)

        layout.addWidget(self.password_input)


        self.checkbox = QCheckBox("İçeriği şifrele")
        self.checkbox.setVisible(False)
        layout.addWidget(self.checkbox)

        self.action_button = QPushButton('Şifrele veya Çöz')
        self.action_button.setEnabled(False)
        self.action_button.setVisible(False)
        self.action_button.clicked.connect(self.process_file_or_folder)

        self.action_button.setStyleSheet("""
            QPushButton {
                background-color: #353535;
                color: white;
                border: 1px solid gray;
                padding: 8px;
                border-radius: 5px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #454545;
            }
            QPushButton:disabled {
                background-color: #2b2b2b;
                color: gray;
            }
        """)

        layout.addWidget(self.action_button)

        self.button_about = QPushButton("...↓...", self)
        self.button_about.setFont(QFont("Arial", 10))
        self.button_about.clicked.connect(self.show_about)

        self.button_about.setStyleSheet("""
            QPushButton {
                background-color: #353535;
                color: white;
                border: 1px solid gray;
                padding: 5px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #454545;
            }
        """)
        layout.addWidget(self.button_about)
     
        self.setLayout(layout)
        self.selected_path = None
        self.setAcceptDrops(True)

        stored_language = self.settings.value('language', 'Türkçe')
        self.language_combo.setCurrentText(stored_language)

    def reset_ui(self):
        language = self.language_combo.currentText()
        self.selected_path = None
        
        self.password_input.clear()
        
        self.password_input.setVisible(False)
        self.checkbox.setVisible(False)
        self.action_button.setVisible(False)
        
        self.action_button.setText('Şifrele veya Çöz' if language == 'Türkçe' else 'Encrypt or Decrypt')
        self.action_button.setEnabled(False)
        self.label.setText('Lütfen bir klasör veya FOLEN dosyası seçmek için tıklayın veya sürükleyip bırakın.' if language == 'Türkçe' else 'Please click or drag and drop a folder or FOLEN file.')
    def setup_language(self):
        current_language = self.language_combo.currentText()
        self.translate_ui(current_language)

    def change_language(self):
        selected_language = self.language_combo.currentText()
        self.translate_ui(selected_language)
        
        self.settings.setValue('language', selected_language)

    def translate_ui(self, language):
        if language == 'English':
            self.setWindowTitle('FOLEN | Folder Encryption')
            self.label.setText('Please click or drag and drop a folder or FOLEN file.')
            self.password_input.setPlaceholderText('Password (4-32 characters)')
            self.checkbox.setText('Encrypt content')
            self.action_button.setText('Encrypt or Decrypt')
        else:  # Türkçe
            self.setWindowTitle('FOLEN | Folder Encryption')
            self.label.setText('Lütfen bir klasör veya FOLEN dosyası seçmek için tıklayın veya sürükleyip bırakın.')
            self.password_input.setPlaceholderText('Parola (4-32 karakter)')
            self.checkbox.setText('İçeriği şifrele')
            self.action_button.setText('Şifrele veya Çöz')

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        urls = event.mimeData().urls()

        if urls:
            self.selected_path = urls[0].toLocalFile()
            self.update_ui_for_selection()

    def get_password(self):
        language = self.language_combo.currentText()
        password = self.password_input.text()
        if len(password) < 4 or len(password) > 32:
            message = 'Parola 4 ile 32 karakter arasında olmalıdır.' if language == 'Türkçe' else 'Password must be between 4 and 32 characters.'
            QMessageBox.warning(self, 'Hata' if language == 'Türkçe' else 'Error', message)
            return None

        # SHA256 ile hash'leme
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(password.encode())
        return digest.finalize()  # AES için 32-byte anahtar döndürür


    def process_file_or_folder(self):
        if not self.selected_path:
            QMessageBox.warning(self, "Error", "No file or folder selected!")
            return

        key = self.get_password()
        if not key:
            return

        if os.path.isdir(self.selected_path):
            self.encrypt_folder(self.selected_path, key)
        elif self.selected_path.endswith('.folen'):
            self.decrypt_file(self.selected_path, key)

    def encrypt_folder(self, folder_path, key):
        try:
            zip_file = folder_path + '.zip'
            encrypted_file = folder_path + '.folen'

            # Create ZIP
            with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(folder_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, folder_path)
                        zipf.write(file_path, arcname)

            # Encrypt ZIP
            with open(zip_file, 'rb') as f:
                data = f.read()

            backend = default_backend()
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
            encryptor = cipher.encryptor()
            encrypted_data = iv + encryptor.update(data) + encryptor.finalize()

            with open(encrypted_file, 'wb') as f:
                f.write(encrypted_data)

            os.remove(zip_file)
            shutil.rmtree(folder_path)

            QMessageBox.information(self, "Başarılı", "Başarıyla şifrelendi.")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Bir hata oluştu: {str(e)}")

    def decrypt_file(self, file_path, key):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            iv = data[:16]
            encrypted_data = data[16:]

            backend = default_backend()
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            zip_file = file_path.replace('.folen', '.zip')
            with open(zip_file, 'wb') as f:
                f.write(decrypted_data)

            decrypted_folder = file_path.replace('.folen', '')
            with zipfile.ZipFile(zip_file, 'r') as zipf:
                zipf.extractall(decrypted_folder)

            os.remove(zip_file)
            os.remove(file_path)

            QMessageBox.information(self, "Başarılı", "Başarıyla çözüldü.")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Bir hata oluştu: {str(e)}")
            
            
            
    def update_ui_for_selection(self):
        if not self.selected_path:
            return

        language = self.language_combo.currentText()

        if os.path.isdir(self.selected_path):
            # Folder selected
            self.action_button.setText('Şifrele' if language == 'Türkçe' else 'Encrypt')
        elif self.selected_path.endswith('.folen'):
            # .folen file selected
            self.action_button.setText('Çöz' if language == 'Türkçe' else 'Decrypt')
        else:
            # Invalid selection
            message = 'Lütfen bir klasör veya .folen dosyası seçin.' if language == 'Türkçe' else 'Please select a folder or .folen file.'
            QMessageBox.warning(self, 'Hata' if language == 'Türkçe' else 'Error', message)
            self.selected_path = None
            self.action_button.setEnabled(False)
            return

        self.password_input.setVisible(True)
        self.checkbox.setVisible(True)
        self.action_button.setVisible(True)
        self.action_button.setEnabled(True)

        self.label.setText(f'Seçilen: {self.selected_path}' if language == 'Türkçe' else f'Selected: {self.selected_path}')
        
            
            
    def show_about(self):
        """Hakkında penceresini gösterir."""
        about_text = (
        "FOLEN | FOLder ENcryption \n\n"
        "Bu uygulama, kullanıcıların dosya ve klasörlerini güvenli bir şekilde şifrelemelerini ve şifreli dosyaları çözmelerini sağlayan kullanımı kolay bir masaüstü uygulamasıdır. AES (Advanced Encryption Standard) algoritmasını kullanarak yüksek güvenlikli şifreleme sağlar, böylece kullanıcı verilerini korur ve sadece doğru şifreyle erişilmesini garanti eder. Bu uygulama, özellikle hassas verilerini güvenli bir şekilde saklamak isteyen bireyler ve kurumlar için tasarlanmıştır.\n\n"
        "Geliştirici: ALG Yazılım Inc.©\n"
        "www.algyazilim.com | info@algyazilim.com\n\n"
        "Fatih ÖNDER (CekToR) | fatih@algyazilim.com\n"
        "GitHub: https://github.com/cektor\n\n"
        "ALG Yazılım Pardus'a Göç'ü Destekler.\n\n"
        "Sürüm: 1.0"
        )
        # Hakkında penceresini doğru şekilde göster
        QMessageBox.information(self, "FOLEN Hakkında", about_text, QMessageBox.Ok)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    if ICON_PATH:
        app.setWindowIcon(QIcon(ICON_PATH))
    window = FolderEncryptorApp()
    window.show()
    sys.exit(app.exec_())
