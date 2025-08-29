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
                             QLineEdit, QMessageBox)
from PyQt5.QtCore import Qt, QTimer

# --- Backend Functions ---

def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Derives a secure encryption key from a password and salt using PBKDF2.

    Args:
        password: The user's password in bytes.
        salt: A random salt in bytes.

    Returns:
        A URL-safe base64-encoded 32-byte key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000, 
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

def encrypt_file(filename, password):
    """
    Encrypts a file using a password. The output file (.enc) contains:
    [16-byte salt][encrypted data]

    Args:
        filename: The path to the file to encrypt.
        password: The password to use for encryption.

    Returns:
        A string indicating the status of the operation.
    """
    if not password:
        return "Error: Password cannot be empty."

    try:
        with open(filename, "rb") as file:
            original_data = file.read()

        original_hash = hashlib.sha256(original_data).hexdigest()
        
        # Prepare the data payload with metadata for integrity checks
        payload = {
            'metadata': {
                'original_filename': os.path.basename(filename),
                'timestamp_utc': datetime.utcnow().isoformat(),
                'original_hash': original_hash
            },
            'data': original_data.hex()
        }
        serialized_payload = json.dumps(payload).encode('utf-8')

        # Generate a random salt for each encryption
        salt = os.urandom(16)
        key = derive_key(password.encode(), salt)
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(serialized_payload)

        new_filename = filename + ".enc"
        
        # Prepend the salt to the encrypted data; it's needed for decryption
        with open(new_filename, "wb") as file:
            file.write(salt)
            file.write(encrypted_data)
        
        return f"Success! Encrypted and saved as '{os.path.basename(new_filename)}'."

    except FileNotFoundError:
        return f"Error: The file '{os.path.basename(filename)}' was not found."
    except Exception as e:
        return f"An error occurred during encryption: {e}"

def decrypt_file(filename, password, overwrite_choice=None):
    """
    Decrypts a file using a password and verifies its integrity.

    Args:
        filename: The path to the .enc file to decrypt.
        password: The password to use for decryption.
        overwrite_choice (str, optional): Pre-selected choice for handling existing files. 
                                         Used to avoid asking the user again. 
                                         Can be 'Overwrite', 'Save As', or 'Cancel'.

    Returns:
        A string indicating the status of the operation.
    """
    if not password:
        return "Error: Password cannot be empty."

    try:
        # The encrypted file is structured as [16-byte salt][encrypted data]
        with open(filename, "rb") as file:
            salt = file.read(16) 
            encrypted_data = file.read()

        # Re-derive the same key using the extracted salt
        key = derive_key(password.encode(), salt)
        fernet = Fernet(key)
        
        decrypted_payload_bytes = fernet.decrypt(encrypted_data)
        payload = json.loads(decrypted_payload_bytes.decode('utf-8'))
        
        metadata = payload['metadata']
        original_data = bytes.fromhex(payload['data'])

        # Verify the hash to ensure the data has not been tampered with
        newly_calculated_hash = hashlib.sha256(original_data).hexdigest()
        stored_hash = metadata['original_hash']

        if newly_calculated_hash != stored_hash:
            return "CRITICAL: TAMPERING DETECTED! Hashes do not match."

        original_filename = metadata['original_filename']
        
    
        if os.path.exists(original_filename) and overwrite_choice is None:
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setText(f"The file '{original_filename}' already exists.")
            msg_box.setInformativeText("Do you want to overwrite it?")
            msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
            msg_box.setDefaultButton(QMessageBox.Cancel)
            
            ret = msg_box.exec_()

            if ret == QMessageBox.Yes:
                pass # Continue to overwrite
            elif ret == QMessageBox.No:
                # User wants to save with a new name
                options = QFileDialog.Options()
                new_save_path, _ = QFileDialog.getSaveFileName(
                    None, "Save Decrypted File As...", original_filename, "All Files (*)", options=options)
                if new_save_path:
                    original_filename = new_save_path
                else:
                    return "Decryption cancelled by user." # User cancelled the save dialog
            else:
                return "Decryption cancelled by user." # User cancelled the overwrite dialog
        
        with open(original_filename, "wb") as file:
            file.write(original_data)

        return f"Success! Decrypted and restored as '{os.path.basename(original_filename)}'."

    except FileNotFoundError:
        return f"Error: The file '{os.path.basename(filename)}' was not found."
    except InvalidToken:
        return "Decryption failed! Invalid password or tampered file."
    except Exception as e:
        return f"An error occurred during decryption: {e}"


class PasswordDialog(QDialog):
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

        self.message_label = QLabel("") # To show error messages like "Passwords do not match"
        self.message_label.setStyleSheet("color: red")

        self.buttons = QPushButton("OK")
        self.buttons.setEnabled(False) # Start with OK disabled
        
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
        """Enable OK button only if passwords are not empty and match."""
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
        """Returns the password if the dialog is accepted."""
        if self.exec_() == QDialog.Accepted:
            return self.pass_input.text()
        return None

# --- GUI Application ---
class SecureStorageApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure File Storage")
        self.setGeometry(100, 100, 500, 200)
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)

        self.create_widgets()
        self.connect_signals()

    def create_widgets(self):
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
        
    def _execute_crypto_operation(self, operation_func, filename, password):
        """Helper function to run crypto, showing busy cursor and handling status updates."""

        QApplication.setOverrideCursor(Qt.WaitCursor)
        
        status = operation_func(filename, password)
        
        QApplication.restoreOverrideCursor() # Restore the cursor
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
                # Use the helper to run the operation
                self._execute_crypto_operation(encrypt_file, filename, password)

    def open_decrypt_dialog(self):
        options = QFileDialog.Options()
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select File to Decrypt", "", "Encrypted Files (*.enc);;All Files (*)", options=options)
            
        if filename:
            # For decryption, we only need the password once. QInputDialog is fine.
            password, ok = QInputDialog.getText(self, "Password Required", 
                                                "Enter the password for the file:", 
                                                QLineEdit.Password)
            if ok and password:
                self.status_label.setText(f"Decrypting '{os.path.basename(filename)}'...")
                # Use the helper to run the operation
                self._execute_crypto_operation(decrypt_file, filename, password)


# --- Main Execution ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecureStorageApp()
    window.show()
    sys.exit(app.exec_())
