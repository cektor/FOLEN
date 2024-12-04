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
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes





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

# Set window icon
    icon_path = self.get_icon_path()
    if icon_path:
        self.setWindowIcon(QIcon(icon_path))



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

        

        # Karanlık Tema Ayarları
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

        # Dil Seçim ComboBox'ı
        self.language_combo = QComboBox()
        self.language_combo.addItems(['Türkçe', 'English'])
        self.language_combo.currentIndexChanged.connect(self.change_language)

        # Arka plan rengini ayarla
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

        
        # Logo ekleme
        if LOGO_PATH:
            self.logo_label = QLabel(self)  # Logo için QLabel oluştur
            pixmap = QPixmap(LOGO_PATH)
            scaled_pixmap = pixmap.scaled(150, 150, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.logo_label.setPixmap(scaled_pixmap)  # Logo resmini set et
            self.logo_label.setAlignment(Qt.AlignCenter)
            layout.addWidget(self.logo_label)  # Logo'yu layout'a ekle

        self.label = QLabel('Lütfen bir klasör veya FOLEN dosyası seçmek için tıklayın veya sürükleyip bırakın.')
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setWordWrap(True)
        layout.addWidget(self.label)

        # Password input and checkbox initially hidden
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText('Parola (4-32 karakter)')
        self.password_input.setVisible(False)

        # Arka plan rengini ve stilini ayarla
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

        # Arka plan rengini ve stilini ayarla
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


        # Hakkında butonu daha küçük olacak ve en altta
        self.button_about = QPushButton("...↓...", self)
        self.button_about.setFont(QFont("Arial", 10))
        self.button_about.clicked.connect(self.show_about)

        # Arka plan rengini ayarla
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

        # Dil ayarını yükle
        stored_language = self.settings.value('language', 'Türkçe')
        self.language_combo.setCurrentText(stored_language)

    def reset_ui(self):
        language = self.language_combo.currentText()
        self.selected_path = None
        
        # Clear password input
        self.password_input.clear()
        
        # Hide password, checkbox, and action button
        self.password_input.setVisible(False)
        self.checkbox.setVisible(False)
        self.action_button.setVisible(False)
        
        self.action_button.setText('Şifrele veya Çöz' if language == 'Türkçe' else 'Encrypt or Decrypt')
        self.action_button.setEnabled(False)
        self.label.setText('Lütfen bir klasör veya FOLEN dosyası seçmek için tıklayın veya sürükleyip bırakın.' if language == 'Türkçe' else 'Please click or drag and drop a folder or FOLEN file.')

    # ... (resten av koden forblir den samme som i forrige versjon)

    def setup_language(self):
        current_language = self.language_combo.currentText()
        self.translate_ui(current_language)

    def change_language(self):
        selected_language = self.language_combo.currentText()
        self.translate_ui(selected_language)
        
        # Dil ayarını kaydet
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

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.select_file_or_folder()

    def select_file_or_folder(self):
        language = self.language_combo.currentText()
        if language == 'English':
            path, _ = QFileDialog.getOpenFileName(self, "Select File", filter="FOLEN File (*.folen)")
            if not path:
                path = QFileDialog.getExistingDirectory(self, "Select Folder")
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Dosya Seç", filter="FOLEN Dosyası (*.folen)")
            if not path:
                path = QFileDialog.getExistingDirectory(self, "Klasör Seç")
        
        if path:
            self.selected_path = path
            self.update_ui_for_selection()

    def update_ui_for_selection(self):
        language = self.language_combo.currentText()
        if os.path.isdir(self.selected_path):
            self.action_button.setText('Şifrele' if language == 'Türkçe' else 'Encrypt')
        elif self.selected_path.endswith('.folen'):
            self.action_button.setText('Çöz' if language == 'Türkçe' else 'Decrypt')
        else:
            message = 'Lütfen bir klasör veya .folen dosyası seçin.' if language == 'Türkçe' else 'Please select a folder or .folen file.'
            QMessageBox.warning(self, 'Hata' if language == 'Türkçe' else 'Error', message)
            self.selected_path = None
            self.action_button.setEnabled(False)
            return
        
        # Show password input, checkbox, and action button
        self.password_input.setVisible(True)
        self.checkbox.setVisible(True)
        self.action_button.setVisible(True)
        
        self.label.setText(f'Seçilen: {self.selected_path}' if language == 'Türkçe' else f'Selected: {self.selected_path}')
        self.action_button.setEnabled(True)

    def get_password(self):
        language = self.language_combo.currentText()
        password = self.password_input.text()
        if len(password) < 4 or len(password) > 32:
            message = 'Parola 4 ile 32 karakter arasında olmalıdır.' if language == 'Türkçe' else 'Password must be between 4 and 32 characters.'
            QMessageBox.warning(self, 'Hata' if language == 'Türkçe' else 'Error', message)
            return None
        return SHA256.new(password.encode()).digest()

    def process_file_or_folder(self):
        language = self.language_combo.currentText()
        if not self.selected_path:
            message = 'Lütfen bir klasör veya dosya seçin.' if language == 'Türkçe' else 'Please select a folder or file.'
            QMessageBox.warning(self, 'Hata' if language == 'Türkçe' else 'Error', message)
            return

        key = self.get_password()
        if not key:
            return

        if os.path.isdir(self.selected_path):
            self.encrypt_folder(self.selected_path, key)
        elif self.selected_path.endswith('.folen'):
            self.decrypt_file(self.selected_path, key)

    def encrypt_folder(self, folder_path, key):
        language = self.language_combo.currentText()
        try:
            zip_file = folder_path + '.zip'
            encrypted_file = folder_path + '.folen'

            with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(folder_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, folder_path)
                        zipf.write(file_path, arcname)

            with open(zip_file, 'rb') as f:
                data = f.read()

            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CFB, iv)
            encrypted_data = iv + cipher.encrypt(data)

            with open(encrypted_file, 'wb') as f:
                f.write(encrypted_data)

            os.remove(zip_file)
            shutil.rmtree(folder_path)
            
            message = 'Başarıyla şifrelendi.' if language == 'Türkçe' else 'Successfully encrypted.'
            QMessageBox.information(self, 'Başarılı' if language == 'Türkçe' else 'Success', message)
            self.reset_ui()
        except Exception as e:
            message = f'Bir hata oluştu: {str(e)}' if language == 'Türkçe' else f'An error occurred: {str(e)}'
            QMessageBox.critical(self, 'Hata' if language == 'Türkçe' else 'Error', message)

    def decrypt_file(self, file_path, key):
        language = self.language_combo.currentText()
        try:
            decrypted_folder = file_path.replace('.folen', '')

            with open(file_path, 'rb') as f:
                data = f.read()

            iv = data[:16]
            encrypted_data = data[16:]
            cipher = AES.new(key, AES.MODE_CFB, iv)
            decrypted_data = cipher.decrypt(encrypted_data)

            zip_file = decrypted_folder + '.zip'
            with open(zip_file, 'wb') as f:
                f.write(decrypted_data)

            with zipfile.ZipFile(zip_file, 'r') as zipf:
                zipf.extractall(decrypted_folder)

            os.remove(zip_file)
            os.remove(file_path)
            
            message = 'Başarıyla çözüldü.' if language == 'Türkçe' else 'Successfully decrypted.'
            QMessageBox.information(self, 'Başarılı' if language == 'Türkçe' else 'Success', message)
            self.reset_ui()
        except Exception as e:
            message = f'Bir hata oluştu: {str(e)}' if language == 'Türkçe' else f'An error occurred: {str(e)}'
            QMessageBox.critical(self, 'Hata' if language == 'Türkçe' else 'Error', message)

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
    window = FolderEncryptorApp()
    window.show()
    sys.exit(app.exec_())
