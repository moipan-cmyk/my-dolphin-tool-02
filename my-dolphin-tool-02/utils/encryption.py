# utils/encryption.py
"""
Encryption utilities for secure client-server communication
Supports AES-256, Fernet, and RSA encryption methods
"""

import os
import base64
import hashlib
import secrets
import json
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify

# Try to import cryptography libraries
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("⚠️ Cryptography library not installed. Run: pip install cryptography")

# Try to import PyCryptodome as fallback
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    PYDOME_AVAILABLE = True
except ImportError:
    PYDOME_AVAILABLE = False

# ==================== CONSTANTS ====================
DEFAULT_KEY_FILE = 'encryption_key.key'
SESSION_KEY_LENGTH = 32
SALT_LENGTH = 16
IV_LENGTH = 16
ITERATIONS = 100000

# ==================== KEY MANAGEMENT ====================

class KeyManager:
    """Manage encryption keys with secure storage"""
    
    def __init__(self, key_dir='keys'):
        self.key_dir = key_dir
        self._ensure_key_dir()
    
    def _ensure_key_dir(self):
        """Create key directory if it doesn't exist"""
        if not os.path.exists(self.key_dir):
            os.makedirs(self.key_dir, mode=0o700)
    
    def generate_master_key(self, key_name='master'):
        """Generate a new master encryption key"""
        if CRYPTO_AVAILABLE:
            key = Fernet.generate_key()
        else:
            key = secrets.token_bytes(32)
        
        key_path = os.path.join(self.key_dir, f'{key_name}.key')
        with open(key_path, 'wb') as f:
            f.write(key)
        os.chmod(key_path, 0o600)
        
        return key
    
    def load_master_key(self, key_name='master'):
        """Load master encryption key from file"""
        key_path = os.path.join(self.key_dir, f'{key_name}.key')
        
        if os.path.exists(key_path):
            with open(key_path, 'rb') as f:
                return f.read()
        else:
            return self.generate_master_key(key_name)
    
    def rotate_key(self, key_name='master'):
        """Rotate encryption key (generate new one)"""
        old_key = self.load_master_key(key_name)
        new_key = self.generate_master_key(f'{key_name}_new')
        
        # Rename new key to master
        old_path = os.path.join(self.key_dir, f'{key_name}.key')
        new_path = os.path.join(self.key_dir, f'{key_name}_new.key')
        backup_path = os.path.join(self.key_dir, f'{key_name}_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.key')
        
        os.rename(old_path, backup_path)
        os.rename(new_path, old_path)
        
        return old_key, new_key

# ==================== FERNET ENCRYPTION ====================

class FernetEncryption:
    """Fernet symmetric encryption (simpler, recommended)"""
    
    def __init__(self, key=None):
        if not CRYPTO_AVAILABLE:
            raise ImportError("Cryptography library is required for Fernet encryption")
        
        self.key = key or Fernet.generate_key()
        self.cipher = Fernet(self.key)
    
    def encrypt(self, data):
        """Encrypt data (string or dict)"""
        if isinstance(data, dict):
            data = json.dumps(data)
        elif not isinstance(data, str):
            data = str(data)
        
        encrypted = self.cipher.encrypt(data.encode('utf-8'))
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt(self, encrypted_data):
        """Decrypt encrypted data"""
        try:
            decoded = base64.b64decode(encrypted_data)
            decrypted = self.cipher.decrypt(decoded)
            result = decrypted.decode('utf-8')
            
            # Try to parse as JSON
            try:
                return json.loads(result)
            except:
                return result
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
    
    @staticmethod
    def generate_key():
        """Generate a new Fernet key"""
        return Fernet.generate_key()
    
    @staticmethod
    def generate_key_from_password(password, salt=None):
        """Generate a key from a password"""
        if salt is None:
            salt = secrets.token_bytes(SALT_LENGTH)
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=ITERATIONS,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

# ==================== AES ENCRYPTION ====================

class AESEncryption:
    """AES-256-CBC encryption for larger payloads"""
    
    def __init__(self, key=None):
        self.key = key or secrets.token_bytes(32)
        self.block_size = AES.block_size if PYDOME_AVAILABLE else 16
    
    def encrypt(self, data):
        """Encrypt data using AES-256-CBC"""
        if isinstance(data, dict):
            data = json.dumps(data)
        elif not isinstance(data, str):
            data = str(data)
        
        if PYDOME_AVAILABLE:
            iv = get_random_bytes(IV_LENGTH)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            padded_data = pad(data.encode('utf-8'), AES.block_size)
            encrypted = cipher.encrypt(padded_data)
            combined = iv + encrypted
            return base64.b64encode(combined).decode('utf-8')
        elif CRYPTO_AVAILABLE:
            iv = secrets.token_bytes(IV_LENGTH)
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Pad data to block size
            padding_length = self.block_size - (len(data) % self.block_size)
            padded_data = data.encode('utf-8') + bytes([padding_length] * padding_length)
            
            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            combined = iv + encrypted
            return base64.b64encode(combined).decode('utf-8')
        else:
            raise ImportError("No crypto library available")
    
    def decrypt(self, encrypted_data):
        """Decrypt AES-256-CBC encrypted data"""
        try:
            combined = base64.b64decode(encrypted_data)
            iv = combined[:IV_LENGTH]
            encrypted = combined[IV_LENGTH:]
            
            if PYDOME_AVAILABLE:
                cipher = AES.new(self.key, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(encrypted)
                unpadded = unpad(decrypted, AES.block_size)
                result = unpadded.decode('utf-8')
            elif CRYPTO_AVAILABLE:
                cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(encrypted) + decryptor.finalize()
                
                # Remove padding
                padding_length = decrypted[-1]
                result = decrypted[:-padding_length].decode('utf-8')
            else:
                raise ImportError("No crypto library available")
            
            # Try to parse as JSON
            try:
                return json.loads(result)
            except:
                return result
                
        except Exception as e:
            print(f"AES decryption error: {e}")
            return None
    
    @staticmethod
    def generate_key():
        """Generate a new AES-256 key"""
        return secrets.token_bytes(32)

# ==================== RSA ENCRYPTION ====================

class RSAEncryption:
    """RSA asymmetric encryption for key exchange"""
    
    def __init__(self, private_key=None, public_key=None):
        if not CRYPTO_AVAILABLE:
            raise ImportError("Cryptography library is required for RSA encryption")
        
        self.private_key = private_key
        self.public_key = public_key
    
    @classmethod
    def generate_keypair(cls, key_size=2048):
        """Generate RSA keypair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        return cls(private_key, public_key)
    
    def encrypt(self, data):
        """Encrypt data with public key"""
        if isinstance(data, dict):
            data = json.dumps(data)
        elif not isinstance(data, str):
            data = str(data)
        
        encrypted = self.public_key.encrypt(
            data.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt(self, encrypted_data):
        """Decrypt data with private key"""
        try:
            decoded = base64.b64decode(encrypted_data)
            decrypted = self.private_key.decrypt(
                decoded,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            result = decrypted.decode('utf-8')
            
            try:
                return json.loads(result)
            except:
                return result
        except Exception as e:
            print(f"RSA decryption error: {e}")
            return None
    
    def export_private_key(self, password=None):
        """Export private key (optionally password protected)"""
        encryption_algorithm = serialization.NoEncryption()
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
    
    def export_public_key(self):
        """Export public key"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    @classmethod
    def load_private_key(cls, key_data, password=None):
        """Load private key from PEM data"""
        if password:
            private_key = serialization.load_pem_private_key(
                key_data,
                password=password.encode(),
                backend=default_backend()
            )
        else:
            private_key = serialization.load_pem_private_key(
                key_data,
                password=None,
                backend=default_backend()
            )
        
        public_key = private_key.public_key()
        return cls(private_key, public_key)
    
    @classmethod
    def load_public_key(cls, key_data):
        """Load public key from PEM data"""
        public_key = serialization.load_pem_public_key(
            key_data,
            backend=default_backend()
        )
        return cls(None, public_key)

# ==================== HYBRID ENCRYPTION ====================

class HybridEncryption:
    """
    Hybrid encryption: RSA for key exchange, AES for data
    Best of both worlds: secure key exchange + fast bulk encryption
    """
    
    def __init__(self):
        self.rsa = RSAEncryption.generate_keypair()
        self.aes_key = None
        self.session_keys = {}
    
    def get_public_key_pem(self):
        """Get public key for client"""
        return self.rsa.export_public_key().decode('utf-8')
    
    def establish_session(self, client_id, encrypted_aes_key):
        """Establish a session by decrypting AES key with RSA"""
        try:
            decrypted = self.rsa.decrypt(encrypted_aes_key)
            if decrypted:
                self.aes_key = base64.b64decode(decrypted)
                self.session_keys[client_id] = self.aes_key
                return True
        except Exception as e:
            print(f"Session establishment error: {e}")
        return False
    
    def encrypt_data(self, data, client_id=None):
        """Encrypt data with session AES key"""
        key = self.session_keys.get(client_id, self.aes_key)
        if not key:
            raise ValueError("No session key established")
        
        aes = AESEncryption(key)
        return aes.encrypt(data)
    
    def decrypt_data(self, encrypted_data, client_id=None):
        """Decrypt data with session AES key"""
        key = self.session_keys.get(client_id, self.aes_key)
        if not key:
            raise ValueError("No session key established")
        
        aes = AESEncryption(key)
        return aes.decrypt(encrypted_data)

# ==================== MAIN ENCRYPTION MANAGER ====================

class EncryptionManager:
    """Main encryption manager for the application"""
    
    def __init__(self, key_dir='keys', encryption_type='fernet'):
        self.key_manager = KeyManager(key_dir)
        self.encryption_type = encryption_type
        self.master_key = self.key_manager.load_master_key()
        
        if encryption_type == 'fernet':
            self.encryption = FernetEncryption(self.master_key)
        elif encryption_type == 'aes':
            self.encryption = AESEncryption(self.master_key)
        elif encryption_type == 'hybrid':
            self.encryption = HybridEncryption()
        else:
            raise ValueError(f"Unknown encryption type: {encryption_type}")
        
        self.client_sessions = {}
    
    def encrypt(self, data):
        """Encrypt data using configured encryption"""
        return self.encryption.encrypt(data)
    
    def decrypt(self, encrypted_data):
        """Decrypt data using configured encryption"""
        return self.encryption.decrypt(encrypted_data)
    
    def create_client_session(self, client_id):
        """Create a new session for a client"""
        session_key = secrets.token_urlsafe(SESSION_KEY_LENGTH)
        self.client_sessions[client_id] = {
            'key': session_key,
            'created': datetime.utcnow(),
            'expires': datetime.utcnow() + timedelta(hours=12)
        }
        return session_key
    
    def validate_client_session(self, client_id, session_key):
        """Validate client session"""
        session = self.client_sessions.get(client_id)
        if session and session['key'] == session_key and session['expires'] > datetime.utcnow():
            return True
        return False
    
    def rotate_keys(self):
        """Rotate encryption keys"""
        old_key, new_key = self.key_manager.rotate_key()
        self.master_key = new_key
        
        if self.encryption_type == 'fernet':
            self.encryption = FernetEncryption(new_key)
        elif self.encryption_type == 'aes':
            self.encryption = AESEncryption(new_key)
        
        return old_key, new_key

# ==================== DECORATORS FOR FLASK ====================

def encrypted_response(f):
    """Decorator to automatically encrypt Flask responses"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
        
        if isinstance(response, tuple):
            data, status_code = response
        else:
            data, status_code = response, 200
        
        # Check if client wants encrypted response
        if request.headers.get('X-Encrypt-Response', 'false').lower() == 'true':
            encryption_manager = get_encryption_manager()
            encrypted = encryption_manager.encrypt(data)
            return jsonify({
                'encrypted': True,
                'data': encrypted
            }), status_code
        
        return jsonify(data), status_code
    return decorated_function

def encrypted_request(f):
    """Decorator to automatically decrypt encrypted requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.is_json:
            data = request.get_json()
            if data and data.get('encrypted'):
                encrypted_payload = data.get('payload')
                if encrypted_payload:
                    encryption_manager = get_encryption_manager()
                    decrypted = encryption_manager.decrypt(encrypted_payload)
                    if decrypted:
                        request._encrypted_data = decrypted if isinstance(decrypted, dict) else json.loads(decrypted)
                    else:
                        return jsonify({'success': False, 'error': 'Failed to decrypt request'}), 400
        
        return f(*args, **kwargs)
    return decorated_function

# ==================== GLOBAL INSTANCE ====================

_encryption_manager = None

def get_encryption_manager(encryption_type='fernet'):
    """Get or create global encryption manager instance"""
    global _encryption_manager
    if _encryption_manager is None:
        _encryption_manager = EncryptionManager(encryption_type=encryption_type)
    return _encryption_manager

# ==================== HELPER FUNCTIONS ====================

def encrypt_data(data):
    """Quick encryption helper"""
    manager = get_encryption_manager()
    return manager.encrypt(data)

def decrypt_data(encrypted_data):
    """Quick decryption helper"""
    manager = get_encryption_manager()
    return manager.decrypt(encrypted_data)

def generate_key():
    """Generate a new encryption key"""
    return FernetEncryption.generate_key()

def hash_data(data, algorithm='sha256'):
    """Hash data using specified algorithm"""
    if algorithm == 'sha256':
        return hashlib.sha256(data.encode()).hexdigest()
    elif algorithm == 'sha512':
        return hashlib.sha512(data.encode()).hexdigest()
    elif algorithm == 'md5':
        return hashlib.md5(data.encode()).hexdigest()
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")

def verify_hash(data, hash_value, algorithm='sha256'):
    """Verify data against hash"""
    return hash_data(data, algorithm) == hash_value

def secure_compare(a, b):
    """Timing-safe string comparison"""
    return secrets.compare_digest(a, b)

def generate_secure_token(length=32):
    """Generate a secure random token"""
    return secrets.token_urlsafe(length)

# ==================== INITIALIZATION ====================

def init_encryption(key_dir='keys', encryption_type='fernet'):
    """Initialize encryption system"""
    global _encryption_manager
    _encryption_manager = EncryptionManager(key_dir, encryption_type)
    return _encryption_manager

# Export commonly used functions
__all__ = [
    'EncryptionManager',
    'FernetEncryption',
    'AESEncryption',
    'RSAEncryption',
    'HybridEncryption',
    'encrypt_data',
    'decrypt_data',
    'generate_key',
    'hash_data',
    'verify_hash',
    'secure_compare',
    'generate_secure_token',
    'get_encryption_manager',
    'init_encryption',
    'encrypted_response',
    'encrypted_request'
]