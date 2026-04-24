from .decorators import admin_required, reseller_required
from .helpers import log_system

# Import encryption module (new)
from .encryption import (
    EncryptionManager,
    FernetEncryption,
    AESEncryption,
    RSAEncryption,
    HybridEncryption,
    encrypt_data,
    decrypt_data,
    generate_key,
    hash_data,
    verify_hash,
    secure_compare,
    generate_secure_token,
    get_encryption_manager,
    init_encryption,
    encrypted_response,
    encrypted_request
)

# Import additional helpers (optional - if you want them)
from .helpers import (
    get_real_ip,
    get_user_agent,
    hash_hwid,
    generate_token,
    success_response,
    error_response,
    validate_email,
    validate_password,
    get_days_remaining,
    deduct_credits,
    add_credits,
    log_device_history,
    format_log_message
)

# Update __all__ to include your existing exports + new ones
__all__ = [
    # Your existing exports
    'admin_required', 
    'reseller_required', 
    'log_system',
    
    # Encryption exports (new)
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
    'encrypted_request',
    
    # Helper exports (new - optional)
    'get_real_ip',
    'get_user_agent',
    'hash_hwid',
    'generate_token',
    'success_response',
    'error_response',
    'validate_email',
    'validate_password',
    'get_days_remaining',
    'deduct_credits',
    'add_credits',
    'log_device_history',
    'format_log_message'
]