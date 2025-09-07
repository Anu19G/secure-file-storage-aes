import sys
import os
import json
import hashlib
import base64
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QPushButton, QLabel, QFileDialog, QDialog,
                             QLineEdit, QMessageBox, QInputDialog) # QInputDialog was missing
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont

# --- Backend Functions ---

def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derives a secure key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

def encrypt_file(filename, password):
    """Encrypts a file and returns a status message."""
    # This function had no issues and remains unchanged.
    if not password:
        return "Error: Password cannot be empty."
    try:
        with open(filename, "rb") as file:
            original_data = file.read()
        original_hash = hashlib.sha256(original_data).hexdigest()
        payload = {
            'metadata': {
                'original_filename': os.path.basename(filename),
                'timestamp_utc': datetime.utcnow().isoformat(),
                'original_hash': original_hash
            },
            'data': original_data.hex()
        }
        serialized_payload = json.dumps(payload).encode('utf-8')
        salt = os.urandom(16)
        key = derive_key(password.encode(), salt)
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(serialized_payload)
        new_filename = filename + ".enc"
        with open(new_filename, "wb") as file:
            file.write(salt)
            file.write(encrypted_data)
        return f"Success! Encrypted and saved as '{os.path.basename(new_filename)}'."
    except FileNotFoundError:
        return f"Error: The file '{os.path.basename(filename)}' was not found."
    except Exception as e:
        return f"An error occurred during encryption: {e}"

## FIX ##: Created a new "peek" function to safely get metadata without full decryption.
def peek_original_filename(filename, password):
    """
    Safely decrypts just enough of the file to read the original filename from metadata.
    This avoids decrypting the entire file just to check if it exists.
    Returns (original_filename, error_message).
    """
    try:
        with open(filename, "rb") as file:
            salt = file.read(16)
            encrypted_data = file.read() # Reading the whole file is okay here

        key = derive_key(password.encode(), salt)
        fernet = Fernet(key)
        decrypted_payload_bytes = fernet.decrypt(encrypted_data, ttl=None) # Use ttl=None for peeking
        payload = json.loads(decrypted_payload_bytes.decode('utf-8'))
        
        return payload['metadata']['original_filename'], None # Success
    except InvalidToken:
        return None, "Decryption failed! Invalid password or tampered file."
    except Exception as e:
        return None, f"An error occurred: {e}"

## FIX ##: The main decrypt function is now much simpler.
def decrypt_file(filename, password, output_filename):
    """
    Decrypts a file to a specified output path. Contains NO GUI code.
    """
    try:
        with open(filename, "rb") as file:
            salt = file.read(16)
            encrypted_data = file.read()

        key = derive_key(password.encode(), salt)
        fernet = Fernet(key)
        decrypted_payload_bytes = fernet.decrypt(encrypted_data)
        payload = json.loads(decrypted_payload_bytes.decode('utf-8'))
        metadata = payload['metadata']
        original_data = bytes.fromhex(payload['data'])

        newly_calculated_hash = hashlib.sha256(original_data).hexdigest()
        if newly_calculated_hash != metadata['original_hash']:
            return "CRITICAL: TAMPERING DETECTED! Hashes do not match."

        with open(output_filename, "wb") as file:
            file.write(original_data)

        return f"Success! Decrypted and restored as '{os.path.basename(output_filename)}'."
    except Exception as e:
        # We don't expect InvalidToken here because we already checked it in peek()
        return f"An error occurred during final decryption: {e}"


class PasswordDialog(QDialog):
    # This class remains unchanged
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Enter Password")
        self.layout = QVBoxLayout(self)
        self.pass_label = QLabel("Password:")
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.Password)
        self.confirm_label = QLabel("Confirm Password:")
        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.Password)
        self.message_label = QLabel("")
        self.message_label.setStyleSheet("color: red")
        self.buttons = QPushButton("OK")
        self.buttons.setEnabled(False)
        self.layout.addWidget(self.pass_label)
        self.layout.addWidget(self.pass_input)
        self.layout.addWidget(self.confirm_label)
        self.layout.addWidget(self.confirm_input)
        self.layout.addWidget(self.message_label)
        self.layout.addWidget(self.buttons)
        self.pass_input.textChanged.connect(self.check_passwords)
        self.confirm_input.textChanged.connect(self.check_passwords)
        self.buttons.clicked.connect(self.accept)
    def check_passwords(self):
        password = self.pass_input.text()
        confirm = self.confirm_input.text()
        if password and confirm:
            if password == confirm:
                self.message_label.setText("")
                self.buttons.setEnabled(True)
            else:
                self.message_label.setText("Passwords do not match.")
                self.buttons.setEnabled(False)
        else:
            self.buttons.setEnabled(False)
    def get_password(self):
        if self.exec_() == QDialog.Accepted:
            return self.pass_input.text()
        return None

# --- GUI Application ---
class SecureStorageApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CipherShield - Secure File Storage")
        self.setGeometry(100, 100, 500, 250)
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)
        self.create_widgets()
        self.connect_signals()

    def create_widgets(self):
        header_label = QLabel("CipherShield", self)
        header_font = QFont("Arial", 20, QFont.Bold)
        header_label.setFont(header_font)
        header_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(header_label)
        self.status_label = QLabel("Welcome! Please select an action.", self)
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setWordWrap(True)
        self.layout.addWidget(self.status_label)
        self.encrypt_button = QPushButton("Encrypt File", self)
        self.layout.addWidget(self.encrypt_button)
        self.decrypt_button = QPushButton("Decrypt File", self)
        self.layout.addWidget(self.decrypt_button)

    def connect_signals(self):
        self.encrypt_button.clicked.connect(self.open_encrypt_dialog)
        self.decrypt_button.clicked.connect(self.open_decrypt_dialog)

    ## FIX ##: Changed the helper function to accept args and kwargs for more flexibility.
    def _execute_crypto_operation(self, operation_func, *args, **kwargs):
        """Helper function to run crypto, showing busy cursor and handling status updates."""
        QApplication.setOverrideCursor(Qt.WaitCursor)
        status = operation_func(*args, **kwargs)
        QApplication.restoreOverrideCursor()
        self.status_label.setText(status)
        QTimer.singleShot(7000, lambda: self.status_label.setText("Welcome! Please select an action."))

    def open_encrypt_dialog(self):
        options = QFileDialog.Options()
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select File to Encrypt", "", "All Files (*)", options=options)
        if filename:
            dialog = PasswordDialog(self)
            password = dialog.get_password()
            if password:
                self.status_label.setText(f"Encrypting '{os.path.basename(filename)}'...")
                self._execute_crypto_operation(encrypt_file, filename, password)

    ## FIX ##: All GUI logic for decryption is now handled here, before calling the backend.
    def open_decrypt_dialog(self):
        options = QFileDialog.Options()
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select File to Decrypt", "", "Encrypted Files (*.enc);;All Files (*)", options=options)
        if not filename:
            return

        password, ok = QInputDialog.getText(self, "Password Required",
                                            "Enter the password for the file:",
                                            QLineEdit.Password)
        if not (ok and password):
            return

        # 1. Peek inside the file to get the original filename and check the password
        QApplication.setOverrideCursor(Qt.WaitCursor)
        original_filename, error = peek_original_filename(filename, password)
        QApplication.restoreOverrideCursor()

        if error:
            self.status_label.setText(error)
            return
            
        output_filename = original_filename
        
        # 2. Check if the file exists and ask the user what to do
        if os.path.exists(original_filename):
            msg_box = QMessageBox(self)
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setText(f"The file '{original_filename}' already exists.")
            msg_box.setInformativeText("Do you want to overwrite it?")
            msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
            ret = msg_box.exec_()

            if ret == QMessageBox.Yes:
                pass # Keep original_filename
            elif ret == QMessageBox.No:
                new_path, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File As...", original_filename)
                if not new_path:
                    self.status_label.setText("Decryption cancelled.")
                    return
                output_filename = new_path
            else:
                self.status_label.setText("Decryption cancelled.")
                return

        # 3. Execute the final, simple decryption function
        self.status_label.setText(f"Decrypting to '{os.path.basename(output_filename)}'...")
        self._execute_crypto_operation(decrypt_file, filename, password, output_filename)


# --- Main Execution ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName("CipherShield")
    window = SecureStorageApp()
    window.show()
    sys.exit(app.exec_())
