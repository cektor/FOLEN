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
        self.setWindowTitle('FOLEN')
        self.setFixedSize(300, 450)

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

        # Önce tüm widget'ları oluştur
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

        self.label = QLabel('Lütfen bir klasör veya FOLEN dosyası seçmek için tıklayın veya sürükleyip bırakın.')
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setWordWrap(True)

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

        self.checkbox = QCheckBox("İçeriği şifrele")
        self.checkbox.setVisible(False)

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
        
        # Layout'ları oluştur
        layout = QVBoxLayout()
        
        # Üst kısım için layout
        top_layout = QVBoxLayout()
        top_layout.addWidget(self.language_combo)
        
        if LOGO_PATH:
            self.logo_label = QLabel(self)
            pixmap = QPixmap(LOGO_PATH)
            scaled_pixmap = pixmap.scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.logo_label.setPixmap(scaled_pixmap)
            self.logo_label.setAlignment(Qt.AlignCenter)
            top_layout.addWidget(self.logo_label)
        
        top_layout.addWidget(self.label)
        
        # Alt kısım için ayrı bir widget ve layout oluştur
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(10, 10, 10, 10)
        
        # Seçim ve işlem widgetları
        selection_layout = QVBoxLayout()
        selection_layout.addWidget(self.password_input)
        selection_layout.addWidget(self.checkbox)
        selection_layout.addWidget(self.action_button)
        
        bottom_layout.addLayout(selection_layout)
        
        # Alt bilgi ve about butonu
        info_label = QLabel("ALG Yazılım Inc.© | www.algyazilim.com")
        info_label.setAlignment(Qt.AlignCenter)
        info_label.setStyleSheet("""
            QLabel {
                color: #666666;
                font-size: 10px;
            }
        """)
        
        bottom_layout.addWidget(info_label)
        bottom_layout.addWidget(self.button_about)
        
        # Ana layout'a ekle
        layout.addLayout(top_layout)
        layout.addStretch(1)  # Esnek boşluk ekle
        layout.addWidget(bottom_widget)
        
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
            # Ana pencere
            self.setWindowTitle('FOLEN')
            self.label.setText('Please click or drag and drop a folder or FOLEN file.')
            self.password_input.setPlaceholderText('Password (4-32 characters)')
            self.checkbox.setText('Encrypt content')
            self.action_button.setText('Encrypt or Decrypt')
            
            # Hata mesajları
            self.password_error = 'Password must be between 4 and 32 characters.'
            self.invalid_selection = 'Please select a folder or FOLEN file.'
            self.error_title = 'Error'
            self.success_title = 'Success'
            self.error_prefix = 'An error occurred: '
            
            # Başarı mesajları
            self.encrypt_success = 'Folder "{}" has been successfully encrypted.'
            self.decrypt_success = 'Folder "{}" has been successfully decrypted.'
            
            # Seçim metni
            self.selected_text = 'Selected: {}'
            
        else:  # Türkçe
            # Ana pencere
            self.setWindowTitle('FOLEN')
            self.label.setText('Lütfen bir klasör veya FOLEN dosyası seçmek için tıklayın veya sürükleyip bırakın.')
            self.password_input.setPlaceholderText('Parola (4-32 karakter)')
            self.checkbox.setText('İçeriği şifrele')
            self.action_button.setText('Şifrele veya Çöz')
            
            # Hata mesajları
            self.password_error = 'Parola 4 ile 32 karakter arasında olmalıdır.'
            self.invalid_selection = 'Lütfen bir klasör veya FOLEN dosyası seçin.'
            self.error_title = 'Hata'
            self.success_title = 'Başarılı'
            self.error_prefix = 'Bir hata oluştu: '
            
            # Başarı mesajları
            self.encrypt_success = '"{}" klasörü başarıyla şifrelendi.'
            self.decrypt_success = '"{}" klasörü başarıyla çözüldü.'
            
            # Seçim metni
            self.selected_text = 'Seçilen: {}'

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
        password = self.password_input.text()
        if len(password) < 4 or len(password) > 32:
            self.show_message(self.error_title, self.password_error)
            return None

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(password.encode())
        return digest.finalize()

    def process_file_or_folder(self):
        if not self.selected_path:
            self.show_message(self.error_title, self.invalid_selection, QMessageBox.Warning)
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

            # Create ZIP without content encryption
            with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(folder_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, folder_path)
                        zipf.write(file_path, arcname)

            # Encrypt ZIP file
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

            # Klasör adını al
            folder_name = os.path.basename(folder_path)
            self.show_message(self.success_title, self.encrypt_success.format(folder_name))
            
        except Exception as e:
            self.show_message(self.error_title, self.error_prefix + str(e))

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

            # Remove ZIP file if it exists
            if os.path.exists(zip_file):
                os.remove(zip_file)
            os.remove(file_path)

            # Klasör adını al
            folder_name = os.path.basename(file_path.replace('.folen', ''))
            self.show_message(self.success_title, self.decrypt_success.format(folder_name))
            
        except Exception as e:
            self.show_message(self.error_title, self.error_prefix + str(e))

    def update_ui_for_selection(self):
        if not self.selected_path:
            return

        if os.path.isdir(self.selected_path):
            self.action_button.setText('Şifrele' if self.language_combo.currentText() == 'Türkçe' else 'Encrypt')
            self.checkbox.setVisible(True)
        elif self.selected_path.endswith('.folen'):
            self.action_button.setText('Çöz' if self.language_combo.currentText() == 'Türkçe' else 'Decrypt')
            self.checkbox.setVisible(False)
        else:
            self.show_message(self.error_title, self.invalid_selection)
            self.selected_path = None
            self.action_button.setEnabled(False)
            return

        self.password_input.setVisible(True)
        self.action_button.setVisible(True)
        self.action_button.setEnabled(True)
        self.label.setText(self.selected_text.format(self.selected_path))

    def show_about(self):
        """Hakkında penceresini gösterir."""
        msg_box = QMessageBox(self)
        language = self.language_combo.currentText()
        
        # Başlık çevirisi
        msg_box.setWindowTitle("FOLEN Hakkında" if language == 'Türkçe' else "About FOLEN")
        
        # QLabel'ı bul ve wordWrap özelliğini ayarla
        for child in msg_box.children():
            if isinstance(child, QLabel):
                child.setWordWrap(True)
                child.setFixedSize(300, 300)
        
        # Dile göre içerik metni
        if language == 'Türkçe':
            about_text = (
                "<div style='color: white; padding: 10px;'>"
                "<h2 style='color: #4A90E2; text-align: center; margin: 10px 0; font-size: 18px;'>"
                "FOLEN | FOLder ENcryption</h2>"
                "<p style='margin: 15px 0; line-height: 1.4; font-size: 12px; text-align: justify;'>"
                "Bu uygulama, kullanıcıların klasörlerini güvenli bir şekilde şifrelemelerini sağlar."
                "</p>"
                "<p style='text-align: center; color: #4A90E2; margin: 10px 0; font-size: 12px;'>"
                "Geliştirici: ALG Yazılım Inc.©</p>"
                "<p style='text-align: center; margin: 5px 0; font-size: 12px;'>"
                "www.algyazilim.com | info@algyazilim.com</p>"
                "<p style='text-align: center; margin: 5px 0; font-size: 12px;'>"
                "Fatih ÖNDER (CekToR)</p>"
                "<p style='text-align: center; margin: 5px 0; font-size: 12px;'>"
                "fatih@algyazilim.com</p>"
                "<p style='text-align: center; margin: 5px 0; font-size: 12px;'>"
                "<a href='https://github.com/cektor' style='color: #4A90E2; text-decoration: none;'>"
                "GitHub: github.com/cektor</a></p>"
                "<p style='text-align: center; color: #4A90E2; margin: 10px 0; font-size: 12px;'>"
                "ALG Yazılım Pardus'a Göç'ü Destekler.</p>"
                "<p style='text-align: center; color: #666666; margin: 5px 0; font-size: 11px;'>"
                "Sürüm: 1.0</p>"
                "</div>"
            )
        else:  # English
            about_text = (
                "<div style='color: white; padding: 10px;'>"
                "<h2 style='color: #4A90E2; text-align: center; margin: 10px 0; font-size: 18px;'>"
                "FOLEN | FOLder ENcryption</h2>"
                "<p style='margin: 15px 0; line-height: 1.4; font-size: 12px; text-align: justify;'>"
                "This application allows users to securely encrypt their folders."
                "</p>"
                "<p style='text-align: center; color: #4A90E2; margin: 10px 0; font-size: 12px;'>"
                "Developer: ALG Software Inc.©</p>"
                "<p style='text-align: center; margin: 5px 0; font-size: 12px;'>"
                "www.algyazilim.com | info@algyazilim.com</p>"
                "<p style='text-align: center; margin: 5px 0; font-size: 12px;'>"
                "Fatih ÖNDER (CekToR)</p>"
                "<p style='text-align: center; margin: 5px 0; font-size: 12px;'>"
                "fatih@algyazilim.com</p>"
                "<p style='text-align: center; margin: 5px 0; font-size: 12px;'>"
                "<a href='https://github.com/cektor' style='color: #4A90E2; text-decoration: none;'>"
                "GitHub: github.com/cektor</a></p>"
                "<p style='text-align: center; color: #4A90E2; margin: 10px 0; font-size: 12px;'>"
                "ALG Software Supports Migration to Pardus.</p>"
                "<p style='text-align: center; color: #666666; margin: 5px 0; font-size: 11px;'>"
                "Version: 1.0</p>"
                "</div>"
            )
        
        msg_box.setText(about_text)
        
        # MessageBox stilini ayarla
        msg_box.setStyleSheet("""
            QMessageBox {
                background-color: #353535;
            }
            QMessageBox QLabel {
                color: white;
                min-width: 400px;
                max-width: 400px;
                background-color: #353535;
                padding: 10px;
            }
            QPushButton {
                background-color: #454545;
                color: white;
                border: none;
                padding: 5px 15px;
                border-radius: 4px;
                min-width: 60px;
                margin: 3px;
            }
            QPushButton:hover {
                background-color: #4A90E2;
            }
        """)
        
        msg_box.setFixedSize(300, 300)
        msg_box.exec_()

    # Genel MessageBox'lar için yardımcı fonksiyon ekle
    def show_message(self, title, message, icon=QMessageBox.Information):
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setIcon(icon)
        
        # MessageBox stilini ayarla
        msg_box.setStyleSheet("""
            QMessageBox {
                background-color: #353535;
            }
            QMessageBox QLabel {
                color: white;
                background-color: #353535;
            }
            QPushButton {
                background-color: #454545;
                color: white;
                border: none;
                padding: 5px 15px;
                border-radius: 4px;
                min-width: 60px;
            }
            QPushButton:hover {
                background-color: #4A90E2;
            }
        """)
        
        # QLabel'ı bul ve özelliklerini ayarla
        for child in msg_box.children():
            if isinstance(child, QLabel) and not child.pixmap():  # İkon hariç diğer label'lar
                child.setWordWrap(True)
                child.setAlignment(Qt.AlignLeft)
                child.setStyleSheet("padding-left: 10px; font-size: 12px;")
        
        return msg_box.exec_()

    def mousePressEvent(self, event):
        self.open_file_dialog()

    def open_file_dialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_dialog = QFileDialog()
        file_dialog.setOptions(options)
        file_dialog.setFileMode(QFileDialog.ExistingFiles)
        file_dialog.setViewMode(QFileDialog.Detail)
        file_dialog.setDirectory(os.path.expanduser("~"))
        file_dialog.setNameFilter("All Files (*);;FOLEN Files (*.folen)")
        if file_dialog.exec_():
            self.selected_path = file_dialog.selectedFiles()[0]
            self.update_ui_for_selection()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    if ICON_PATH:
        app.setWindowIcon(QIcon(ICON_PATH))
    window = FolderEncryptorApp()
    window.show()
    sys.exit(app.exec_())