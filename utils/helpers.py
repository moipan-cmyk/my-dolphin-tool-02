# utils/helpers.py (preserving your existing log_system)
"""
Helper utilities - preserves existing log_system function
"""

import hashlib
import secrets
from datetime import datetime, timedelta
from flask import request
from database import db, SystemLog

# ==================== YOUR EXISTING LOG_SYSTEM (PRESERVED) ====================

def log_system(user_id, log_type, message, request=None):
    """Create system log entry."""
    try:
        ip = request.remote_addr if request else None
        ua = request.user_agent.string if request and request.user_agent else None
        log = SystemLog(
            user_id=user_id,
            log_type=log_type,
            message=message[:500],
            ip_address=ip,
            user_agent=ua[:500] if ua else None
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Failed to create system log: {e}")

# ==================== NEW HELPER FUNCTIONS ====================

def log_system_action(user_id, log_type, message, request_obj=None):
    """Wrapper for log_system to maintain compatibility"""
    log_system(user_id, log_type, message, request_obj)

def log_device_history(user_id, action, device_id=None, device_name=None, reason=None, request_obj=None):
    """Log device history entry"""
    try:
        from database import db, DeviceHistory
        
        ip = request_obj.remote_addr if request_obj else None
        ua = request_obj.user_agent.string if request_obj and request_obj.user_agent else None
        
        history = DeviceHistory(
            user_id=user_id,
            device_id=device_id,
            device_name=device_name,
            action=action,
            reason=reason,
            ip_address=ip,
            user_agent=ua[:500] if ua else None
        )
        db.session.add(history)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        print(f"Error logging device history: {e}")
        return False

def log_encryption_event(user_id, event_type, details, request_obj=None):
    """Log encryption-related events"""
    log_system(user_id, f"encryption_{event_type}", details, request_obj)

def get_real_ip():
    """Get real IP address behind proxy"""
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr

def get_user_agent():
    """Get user agent from request"""
    return request.headers.get('User-Agent', 'Unknown')[:500]

def is_mobile_request():
    """Check if request is from mobile device"""
    user_agent = request.headers.get('User-Agent', '').lower()
    mobile_keywords = ['android', 'iphone', 'ipad', 'mobile', 'webos']
    return any(keyword in user_agent for keyword in mobile_keywords)

def hash_hwid(hwid):
    """Hash HWID before storing"""
    if not hwid:
        return None
    return hashlib.sha256(hwid.encode()).hexdigest()

def hash_ip(ip_address):
    """Hash IP address for privacy"""
    if not ip_address:
        return None
    return hashlib.sha256(ip_address.encode()).hexdigest()

def generate_token(length=32):
    """Generate secure random token"""
    return secrets.token_urlsafe(length)

def generate_otp(length=6):
    """Generate numeric OTP"""
    return ''.join([str(secrets.randbelow(10)) for _ in range(length)])

def generate_secure_password(length=12):
    """Generate a secure random password"""
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()'
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def get_next_admission_number():
    """Get next admission number for new user"""
    try:
        from database import db, User
        
        last_user = User.query.order_by(User.admission_number.desc()).first()
        if last_user and last_user.admission_number:
            return last_user.admission_number + 1
        return 1000
    except Exception as e:
        print(f"Error getting admission number: {e}")
        return 1000

def get_user_by_identifier(identifier):
    """Get user by email, username, or admission number"""
    try:
        from database import User
        
        user = User.query.filter_by(email=identifier).first()
        if user:
            return user
        
        user = User.query.filter_by(username=identifier).first()
        if user:
            return user
        
        if identifier.isdigit():
            user = User.query.filter_by(admission_number=int(identifier)).first()
            if user:
                return user
        
        return None
    except Exception as e:
        print(f"Error finding user: {e}")
        return None

def calculate_license_expiry(license_type):
    """Calculate license expiry date based on type"""
    durations = {
        '24_hours': timedelta(hours=24),
        '2_days': timedelta(days=2),
        '3_days': timedelta(days=3),
        '7_days': timedelta(days=7),
        '1_month': timedelta(days=30),
        '3_months': timedelta(days=90),
        '6_months': timedelta(days=180),
        '1_year': timedelta(days=365),
        'Trial': timedelta(hours=12),
        'Fair': timedelta(days=90),
        'Good': timedelta(days=180),
        'Excellent': timedelta(days=365),
        'Lifetime': timedelta(days=3650)
    }
    
    duration = durations.get(license_type, timedelta(days=30))
    return datetime.utcnow() + duration

def get_device_limit_for_license(license_type):
    """Get device limit based on license type"""
    limits = {
        '24_hours': 1,
        '2_days': 1,
        '3_days': 1,
        '7_days': 1,
        '1_month': 1,
        '3_months': 1,
        '6_months': 1,
        '1_year': 1,
        'Trial': 1,
        'Fair': 10,
        'Good': 25,
        'Excellent': 55,
        'Lifetime': 99
    }
    
    return limits.get(license_type, 1)

def is_license_valid(license_expiry_date):
    """Check if license is still valid"""
    if not license_expiry_date:
        return False
    return license_expiry_date > datetime.utcnow()

def get_days_remaining(license_expiry_date):
    """Get number of days remaining on license"""
    if not license_expiry_date:
        return 0
    days = (license_expiry_date - datetime.utcnow()).days
    return max(0, days)

def get_command_cost(tab, mode, action):
    """Get cost for a specific command"""
    costs = {
        'xiaomi': 5,
        'mediatek': 3,
        'unisoc': 3,
        'samsung': 4,
        'hxd': 2
    }
    
    action_costs = {
        'factory_reset': 5,
        'frp': 3,
        'reset_frp': 3,
        'read_info': 1,
        'unlock': 5
    }
    
    return action_costs.get(action, costs.get(tab, 2))

def deduct_credits(user, amount, description, request_obj=None):
    """Deduct credits from user with transaction record"""
    try:
        from database import db, CreditTransaction
        
        if (user.credits or 0) < amount:
            return False, f"Insufficient credits. Need {amount} credits"
        
        user.credits = (user.credits or 0) - amount
        
        transaction = CreditTransaction(
            user_id=user.id,
            amount=-amount,
            transaction_type='command_usage',
            description=description
        )
        db.session.add(transaction)
        db.session.commit()
        
        log_system(user.id, 'credit_deduct', f"Deducted {amount} credits: {description}", request_obj)
        
        return True, "Credits deducted successfully"
        
    except Exception as e:
        db.session.rollback()
        return False, str(e)

def add_credits(user, amount, description, admin_id=None, request_obj=None):
    """Add credits to user with transaction record"""
    try:
        from database import db, CreditTransaction
        
        old_balance = user.credits or 0
        user.credits = old_balance + amount
        
        transaction = CreditTransaction(
            user_id=user.id,
            amount=amount,
            transaction_type='admin_add' if admin_id else 'purchase',
            description=description,
            created_by=admin_id
        )
        db.session.add(transaction)
        db.session.commit()
        
        log_system(admin_id or user.id, 'credit_add', f"Added {amount} credits to {user.username}: {description}", request_obj)
        
        return True, f"Added {amount} credits. New balance: {user.credits}"
        
    except Exception as e:
        db.session.rollback()
        return False, str(e)

def success_response(data=None, message="Success"):
    """Create success response"""
    response = {'success': True, 'message': message}
    if data is not None:
        response['data'] = data
    return response

def error_response(message, code=400, details=None):
    """Create error response"""
    response = {'success': False, 'error': message, 'code': code}
    if details:
        response['details'] = details
    return response, code

def paginate_response(items, page, limit, total):
    """Create paginated response"""
    return {
        'success': True,
        'items': items,
        'pagination': {
            'page': page,
            'limit': limit,
            'total': total,
            'pages': (total + limit - 1) // limit
        }
    }

def validate_email(email):
    """Validate email format"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_password(password):
    """Validate password strength"""
    if len(password) < 6:
        return False, "Password must be at least 6 characters"
    if len(password) > 128:
        return False, "Password must be less than 128 characters"
    return True, "Password is valid"

def validate_hwid(hwid):
    """Validate HWID format"""
    if not hwid:
        return False, "HWID is required"
    if len(hwid) < 8:
        return False, "Invalid HWID format"
    return True, "Valid HWID"

def validate_username(username):
    """Validate username format"""
    if not username:
        return False, "Username is required"
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    if len(username) > 80:
        return False, "Username must be less than 80 characters"
    return True, "Valid username"

def format_log_message(step_type, message, emoji=True):
    """Format log messages with emojis for better display"""
    emoji_map = {
        'info': 'ℹ️', 'success': '✅', 'error': '❌',
        'warning': '⚠️', 'progress': '⏳', 'device': '📱',
        'scan': '🔍', 'connection': '🔌', 'step': '⚙️', 'complete': '🎉'
    }
    if emoji and step_type in emoji_map:
        return f"{emoji_map[step_type]} {message}"
    return message

def format_time_ago(dt):
    """Format datetime as time ago string"""
    if not dt:
        return "Never"
    now = datetime.utcnow()
    diff = now - dt
    if diff.days > 365:
        years = diff.days // 365
        return f"{years} year{'s' if years != 1 else ''} ago"
    elif diff.days > 30:
        months = diff.days // 30
        return f"{months} month{'s' if months != 1 else ''} ago"
    elif diff.days > 0:
        return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    else:
        return "Just now"

def truncate_string(s, max_length=100, suffix="..."):
    """Truncate a string to max length"""
    if not s:
        return ""
    if len(s) <= max_length:
        return s
    return s[:max_length - len(suffix)] + suffixfrom .decorators import admin_required, reseller_required
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