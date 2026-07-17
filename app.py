from flask import send_from_directory
import os 
import sys
import secrets
import hashlib
from flask import Flask, request, flash, redirect, jsonify, render_template, url_for, session as flask_session
from flask_login import LoginManager, login_required, current_user, login_user, logout_user
from config import Config
from database import db, User, Device, UserSession, DeviceHistory, CreditTransaction, SystemLog
from sqlalchemy import text, func, and_, or_
from datetime import datetime, timedelta
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
import traceback
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
# Add these to your imports at the top
from database import db, User, Device, UserSession, DeviceHistory, CreditTransaction, SystemLog, CommandUsage, LoginAttempt
from database import check_command_limit, increment_command_count, check_login_limit, log_login_attempt
from database import db, User, Device, UserSession, DeviceHistory, CreditTransaction, SystemLog, CommandUsage, LoginAttempt, SamsungOrder, ServerStatus
from sqlalchemy import func
# ==================== GSM MANAGER OTP PROVIDER ====================
import hmac
import time
import requests
from dotenv import load_dotenv
import time
import json as json_module

# Load environment variables
load_dotenv()

# GSM Manager Configuration
GSM_API_URL = os.getenv('DHRU_API_URL')  # https://gsmmanager.com/public
GSM_USERNAME = os.getenv('DHRU_USERNAME')  # clintonmoipan34@gmail.com
GSM_API_KEY = os.getenv('DHRU_API_KEY')  # O6LS-KYUJ-PLJ4-TVQ6-NIWQ-AQ


class GSMManagerOTPProvider:
    """GSM Manager API Provider for OTP generation"""
    
    def __init__(self):
        self.api_url = GSM_API_URL
        self.username = GSM_USERNAME
        self.api_key = GSM_API_KEY
        self.session = requests.Session()
        self.session.timeout = 30
    
    def _generate_signature(self, params: dict) -> str:
        """Generate HMAC-SHA256 signature for API request"""
        sorted_params = sorted(params.items())
        signature_string = '&'.join([f"{k}={v}" for k, v in sorted_params])
        
        signature = hmac.new(
            self.api_key.encode(),
            signature_string.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    def place_order(self, service_name: str, quantity: int = 1, **kwargs) -> dict:
        """Place order on GSM Manager using Dhru Fusion API pattern"""
        
        payload = {
            'action': 'generate_otp',
            'service': service_name,
            'quantity': quantity,
            'username': self.username,
            'api_key': self.api_key,
            'timestamp': int(time.time())
        }
        
        # Add optional fields
        if kwargs.get('model'):
            payload['model'] = kwargs['model']
        if kwargs.get('imei'):
            payload['imei'] = kwargs['imei']
        
        payload['signature'] = self._generate_signature(payload)
        
        try:
            endpoint = f"{self.api_url}/api/otp/generate"
            print(f"📡 [GSM] Placing order for: {service_name}")
            print(f"📡 [GSM] URL: {endpoint}")
            
            response = self.session.post(
                endpoint,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            print(f"📡 [GSM] Response Status: {response.status_code}")
            
            # Try to extract error message from HTML if not JSON
            if response.status_code != 200 or 'text/html' in response.headers.get('Content-Type', ''):
                # Try to find the error message in HTML
                import re
                # Look for title or error message
                title_match = re.search(r'<title>(.*?)</title>', response.text)
                if title_match:
                    error_msg = title_match.group(1)
                else:
                    # Look for common error patterns
                    error_match = re.search(r'(Insufficient credits|Not enough credits|Balance too low)', response.text, re.IGNORECASE)
                    if error_match:
                        error_msg = error_match.group(1)
                    else:
                        error_msg = "Unknown error (possibly insufficient credits)"
                
                print(f"❌ [GSM] Error: {error_msg}")
                return {
                    'success': False,
                    'error': f'server to server error.contact admin for more info.',
                    'details': error_msg
                }
            
            # If JSON response
            try:
                result = response.json()
                print(f"📡 [GSM] Response: {result}")
                
                if result.get('status') == 'success':
                    data = result.get('data', {})
                    return {
                        'success': True,
                        'order_id': data.get('order_id'),
                        'status': data.get('status', 'pending'),
                        'price': data.get('price'),
                        'currency': data.get('currency', 'USD'),
                        'otp_code': data.get('otp_code')
                    }
                else:
                    return {
                        'success': False,
                        'error': result.get('message', 'Failed to generate OTP')
                    }
            except json.JSONDecodeError:
                return {'success': False, 'error': 'Invalid response from server'}
                
        except Exception as e:
            print(f"❌ [GSM] Exception: {e}")
            return {'success': False, 'error': str(e)}
            
    def check_order_status(self, order_id: str) -> dict:
        """Check order status using Dhru Fusion API pattern"""
        
        payload = {
            'action': 'order_status',
            'order_id': order_id,
            'username': self.username,
            'api_key': self.api_key,
            'timestamp': int(time.time())
        }
        
        payload['signature'] = self._generate_signature(payload)
        
        try:
            endpoint = f"{self.api_url}/api/order/status"
            print(f"📡 [GSM] Checking status: {order_id}")
            
            response = self.session.post(
                endpoint,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                try:
                    result = response.json()
                    if result.get('status') == 'success':
                        data = result.get('data', {})
                        return {
                            'success': True,
                            'order_id': order_id,
                            'status': data.get('status'),
                            'otp_code': data.get('otp_code'),
                            'delivery_time': data.get('delivery_time')
                        }
                    else:
                        return {'success': False, 'error': result.get('message')}
                except:
                    return {'success': False, 'error': 'Invalid response'}
            else:
                return {'success': False, 'error': f'HTTP {response.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def generate_otp(self, otp_type: str, model: str = None, imei: str = None) -> dict:
        """
        Generate OTP from GSM Manager
        Uses exact service names from GSM Manager
        """
        
        # Complete service mapping based on GSM Manager services
        service_mapping = {
            # OPPO Service
            'oppo_flash': {
                'service_name': 'OPlusPro Login - OppO OTP',
                'name': 'OPPO Flash OTP',
                'delivery': 'Minutes',
                'price_usd': 23,
                'your_price_credits': 35
            },
            
            # OnePlus Service
            'oneplus': {
                'service_name': 'OplusPro Login OTP (OnePlus)',
                'name': 'OnePlus OTP',
                'delivery': 'Minutes',
                'price_usd': 10,
                'your_price_credits': 20
            },
            
            # Realme Service
            'realme_frp': {
                'service_name': 'OplusPro OTP (Realme MTK One Click FRP Reset)',
                'name': 'Realme MTK One Click FRP Reset',
                'delivery': 'Instant',
                'price_usd': 5,
                'your_price_credits': 12
            },
            'realme_mtk': {
                'service_name': 'OplusPro OTP (Realme MTK One Click FRP Reset)',
                'name': 'Realme MTK OTP',
                'delivery': 'Instant',
                'price_usd': 5,
                'your_price_credits': 12
            },
            
            # Tecno/Infinix/iTel AntiCrack
            'tecno_anticrack': {
                'service_name': 'OPlusPro OTP (Tecno/Infinix/iTel Loader AntiCrack)',
                'name': 'Tecno/Infinix/iTel Loader AntiCrack',
                'delivery': 'Instant',
                'price_usd': 10,
                'your_price_credits': 18
            },
            'tecno_anticrack_p7': {
                'service_name': 'OPlusPro OTP (Tecno/Infinix/iTel Loader AntiCrack)',
                'name': 'Tecno/Infinix/iTel AntiCrack P7',
                'delivery': 'Instant',
                'price_usd': 10,
                'your_price_credits': 18
            },
            
            # Tecno/Infinix/iTel Auth Flash
            'tecno_auth_mtk': {
                'service_name': 'OPlusPro OTP (Tecno/Infinix/iTel Loader Auth Flash)',
                'name': 'Tecno/Infinix/iTel Loader Auth Flash',
                'delivery': 'Instant',
                'price_usd': 9,
                'your_price_credits': 16
            },
            'infinix_auth_mtk': {
                'service_name': 'OPlusPro OTP (Tecno/Infinix/iTel Loader Auth Flash)',
                'name': 'Infinix Auth Flash MTK',
                'delivery': 'Instant',
                'price_usd': 9,
                'your_price_credits': 16
            },
            'tecno_auth_spd': {
                'service_name': 'OPlusPro OTP (Tecno/Infinix/iTel Loader Auth Flash)',
                'name': 'Tecno/Infinix/iTel Auth Flash SPD',
                'delivery': 'Instant',
                'price_usd': 9,
                'your_price_credits': 16
            },
            
            # Xiaomi Service
            'xiaomi_frp': {
                'service_name': 'OplusPro OTP (Xiaomi FRP ONE CLICK)',
                'name': 'Xiaomi FRP One Click',
                'delivery': 'Instant',
                'price_usd': 4.5,
                'your_price_credits': 10
            },
            'xiaomi_otp': {
                'service_name': 'OplusPro OTP (Xiaomi FRP ONE CLICK)',
                'name': 'Xiaomi OTP',
                'delivery': 'Instant',
                'price_usd': 4.5,
                'your_price_credits': 10
            },
        }
        
        # Check if OTP type is supported
        if otp_type not in service_mapping:
            return {
                'success': False,
                'error': f'OTP type "{otp_type}" not supported',
                'supported_types': list(service_mapping.keys())
            }
        
        mapping = service_mapping[otp_type]
        service_name = mapping['service_name']
        
        print(f"📡 [GSM] Placing order for {mapping['name']}")
        print(f"   Service: {service_name}")
        print(f"   Delivery: {mapping['delivery']}")
        print(f"   Provider Price: ${mapping['price_usd']} USD")
        print(f"   Your Price: {mapping['your_price_credits']} credits")
        
        # Place order
        order_result = self.place_order(service_name, quantity=1, model=model, imei=imei)
        
        if not order_result.get('success'):
            return order_result
        
        order_id = order_result.get('order_id')
        
        # For instant delivery, check status immediately
        if mapping['delivery'] == 'Instant':
            # Wait a moment for processing
            time.sleep(3)
            
            # Check status to get OTP
            status_result = self.check_order_status(order_id)
            
            if status_result.get('success') and status_result.get('otp_code'):
                return {
                    'success': True,
                    'otp_code': status_result.get('otp_code'),
                    'order_id': order_id,
                    'service_name': mapping['name'],
                    'delivery': 'instant',
                    'price_usd': mapping['price_usd'],
                    'your_price_credits': mapping['your_price_credits']
                }
            else:
                return {
                    'success': True,
                    'pending': True,
                    'order_id': order_id,
                    'service_name': mapping['name'],
                    'delivery': 'instant',
                    'message': 'Order placed. OTP is being processed.'
                }
        else:
            # For minutes delivery, return pending
            return {
                'success': True,
                'pending': True,
                'order_id': order_id,
                'service_name': mapping['name'],
                'delivery': 'minutes',
                'message': f'Order placed. Delivery in {mapping["delivery"]}. Please check status shortly.'
            } 
# ==================== YOUR OTP_TYPES WITH YOUR PRICES (IN CREDITS) ====================

OTP_TYPES = {
    # OPPO (Your price: 35 credits - Provider: $23 USD)
    'oppo_flash': {'name': 'OPPO Flash OTP', 'cost': 35, 'provider_price_usd': 23},
    
    # OnePlus (Your price: 20 credits - Provider: $10 USD)
    'oneplus': {'name': 'OnePlus OTP', 'cost': 20, 'provider_price_usd': 10},
    
    # Realme (Your price: 12 credits - Provider: $5 USD)
    'realme_frp': {'name': 'Realme MTK One Click FRP Reset', 'cost': 12, 'provider_price_usd': 5},
    'realme_mtk': {'name': 'Realme MTK OTP', 'cost': 12, 'provider_price_usd': 5},
    
    # Tecno/Infinix AntiCrack (Your price: 18 credits - Provider: $10 USD)
    'tecno_anticrack': {'name': 'Tecno/Infinix/iTel Loader AntiCrack', 'cost': 18, 'provider_price_usd': 10},
    'tecno_anticrack_p7': {'name': 'Tecno/Infinix/iTel AntiCrack P7', 'cost': 18, 'provider_price_usd': 10},
    
    # Tecno/Infinix Auth Flash (Your price: 16 credits - Provider: $9 USD)
    'tecno_auth_mtk': {'name': 'Tecno/Infinix/iTel Loader Auth Flash', 'cost': 16, 'provider_price_usd': 9},
    'infinix_auth_mtk': {'name': 'Infinix Auth Flash MTK', 'cost': 16, 'provider_price_usd': 9},
    'tecno_auth_spd': {'name': 'Tecno/Infinix/iTel Auth Flash SPD', 'cost': 16, 'provider_price_usd': 9},
    'tecno_cpid': {'name': 'Tecno/Infinix/iTel CPID', 'cost': 25, 'provider_price_usd': 15},
    
    # Xiaomi (Your price: 10 credits - Provider: $4.50 USD)
    'xiaomi_frp': {'name': 'Xiaomi FRP One Click', 'cost': 10, 'provider_price_usd': 4.5},
    'xiaomi_otp': {'name': 'Xiaomi OTP', 'cost': 10, 'provider_price_usd': 4.5},
}

# ==================== CONSTANTS ====================
SESSION_DURATION_HOURS = 12       # Hardware binding: 12 hours
SESSION_INACTIVITY_MINUTES = 30   # Inactivity timeout: 30 minutes
DEVICE_RESET_COST = 2

# ==================== SAMSUNG FRP CONSTANTS ====================
SAMSUNG_FRP_PRICES = {
    '13': 30,
    '14': 30,
    '15': 50,
    '16': 80
}

# Samsung FRP server URL (for external service)
SAMSUNG_FRP_SERVER_URL = os.environ.get('SAMSUNG_FRP_SERVER_URL', 'https://samsung-frp-api.example.com')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

print("\n" + "="*60)
print("🔍 Starting application")
print("="*60)

login_manager = LoginManager()

def hash_hwid(hwid):
    """Hash HWID before storing"""
    if not hwid:
        return None
    return hashlib.sha256(hwid.encode()).hexdigest()

def get_user_from_token():
    """Extract user from session token - reusable helper"""
    session_token = None
    
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        session_token = auth_header.split(' ')[1]
    
    if not session_token and request.is_json:
        data = request.get_json()
        if data:
            session_token = data.get('session_token')
    
    if not session_token:
        session_token = request.args.get('session_token')
    
    if session_token:
        session_obj = UserSession.query.filter_by(
            session_token=session_token,
            is_active=True
        ).filter(UserSession.expires_at > datetime.utcnow()).first()
        if session_obj:
            return User.query.get(session_obj.user_id)
    
    return None

def get_real_ip():
    """Get real IP address behind proxy"""
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr

# ========== ADD THIS FUNCTION RIGHT HERE ==========
def add_security_columns():
    """Add security tracking columns to users table"""
    try:
        from sqlalchemy import text
        
        # Add security tracking columns to users table
        security_columns = [
            ('ban_reason', "ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_reason VARCHAR(500)"),
            ('tamper_attempt_count', "ALTER TABLE users ADD COLUMN IF NOT EXISTS tamper_attempt_count INTEGER DEFAULT 0"),
            ('last_tamper_at', "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_tamper_at TIMESTAMP"),
            ('ban_type', "ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_type VARCHAR(50) DEFAULT 'manual'")
        ]
        
        for col_name, alter_stmt in security_columns:
            try:
                db.session.execute(text(alter_stmt))
                db.session.commit()
                print(f"✅ Added security column: {col_name}")
            except Exception as e:
                if "duplicate column" not in str(e).lower():
                    print(f"⚠️ Column {col_name}: {str(e)[:50]}")
                db.session.rollback()
        
        # Create security_challenges table
        db.session.execute(text("""
            CREATE TABLE IF NOT EXISTS security_challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                challenge_id TEXT UNIQUE NOT NULL,
                challenge TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """))
        
        # Create challenge_logs table
        db.session.execute(text("""
            CREATE TABLE IF NOT EXISTS challenge_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                challenge_id TEXT NOT NULL,
                success BOOLEAN DEFAULT 0,
                device_fingerprint TEXT,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """))
        
        # Create tamper_reports table
        db.session.execute(text("""
            CREATE TABLE IF NOT EXISTS tamper_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                device_fingerprint TEXT NOT NULL,
                tamper_flags TEXT NOT NULL,
                ip_address TEXT,
                username TEXT,
                hostname TEXT,
                reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        
        # Create tamper_counters table
        db.session.execute(text("""
            CREATE TABLE IF NOT EXISTS tamper_counters (
                email TEXT PRIMARY KEY,
                tamper_count INTEGER DEFAULT 0,
                last_tamper_at TIMESTAMP,
                banned_at TIMESTAMP,
                ban_reason TEXT
            )
        """))
        
        db.session.commit()
        print("✅ Security tables and columns created successfully")
        
    except Exception as e:
        print(f"⚠️ Security columns warning: {e}")
        db.session.rollback()
# ========== END OF ADDED FUNCTION ==========

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    if not app.config.get('SECRET_KEY'):
        app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'
    
    # Initialize database first
    db.init_app(app)
    
    # ==================== RATE LIMITING (FIXED) ====================
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    
    # Custom key function for authenticated users - IMPORT current_user INSIDE the function
    def get_user_key():
        from flask_login import current_user  # Import here to avoid circular reference
        try:
            if current_user and current_user.is_authenticated:
                return f"user:{current_user.id}"
        except (RuntimeError, AttributeError):
            # current_user not available yet, fall back to IP
            pass
        return get_remote_address()
    
    # Create limiter with the fixed key function
    limiter = Limiter(
        app=app,
        key_func=get_user_key,  # Use the fixed function from the start
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://",  # Change to os.environ.get('REDIS_URL', 'memory://') for production
        headers_enabled=True  # Add rate limit headers to responses
    )

        # Optional: Add rate limit error handler for JSON responses
    @app.errorhandler(429)
    def ratelimit_handler(e):
        """Return JSON instead of HTML for rate limit errors"""
        return jsonify({
            'success': False,
            'error': 'Too many requests. Please slow down.',
            'code': 'RATE_LIMIT_EXCEEDED',
            'retry_after': 60
        }), 429
    
    # Initialize login manager AFTER rate limiter
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = None
    
    # ========== THIS NEEDS TO BE INDENTED CORRECTLY ==========
    with app.app_context():
        db.create_all()
        print("✅ Database tables created/verified")

        # ==================== RUN DATABASE MIGRATIONS ====================
        from database import run_migrations
        run_migrations()
        
        # ==================== ADD DEVICE BINDING COLUMNS ====================
        try:
            from sqlalchemy import text
            
            # Add device binding columns to users table
            binding_columns = [
                ('bound_hwid_hash', "ALTER TABLE users ADD COLUMN IF NOT EXISTS bound_hwid_hash VARCHAR(256)"),
                ('bound_pc_manufacturer', "ALTER TABLE users ADD COLUMN IF NOT EXISTS bound_pc_manufacturer VARCHAR(200)"),
                ('bound_windows_version', "ALTER TABLE users ADD COLUMN IF NOT EXISTS bound_windows_version VARCHAR(100)"),
                ('bound_hardware_fingerprint', "ALTER TABLE users ADD COLUMN IF NOT EXISTS bound_hardware_fingerprint VARCHAR(256)"),
                ('bound_system_info', "ALTER TABLE users ADD COLUMN IF NOT EXISTS bound_system_info TEXT"),
                ('bound_ip_address', "ALTER TABLE users ADD COLUMN IF NOT EXISTS bound_ip_address VARCHAR(50)"),
                ('bound_at', "ALTER TABLE users ADD COLUMN IF NOT EXISTS bound_at TIMESTAMP"),
                ('last_verified_at', "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMP"),
                ('verification_failures', "ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_failures INTEGER DEFAULT 0"),
                ('is_verified_device', "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified_device BOOLEAN DEFAULT FALSE"),
            ]
            
            for col_name, alter_stmt in binding_columns:
                try:
                    db.session.execute(text(alter_stmt))
                    db.session.commit()
                    print(f"✅ Added column: {col_name}")
                except Exception as e:
                    # Column might already exist
                    print(f"⚠️ Column {col_name} - {str(e)[:50]}")
                    db.session.rollback()
            
            # Add columns to devices table
            device_columns = [
                ('pc_manufacturer', "ALTER TABLE devices ADD COLUMN IF NOT EXISTS pc_manufacturer VARCHAR(200)"),
                ('windows_version', "ALTER TABLE devices ADD COLUMN IF NOT EXISTS windows_version VARCHAR(100)"),
                ('hardware_fingerprint', "ALTER TABLE devices ADD COLUMN IF NOT EXISTS hardware_fingerprint VARCHAR(256)"),
            ]
            
            for col_name, alter_stmt in device_columns:
                try:
                    db.session.execute(text(alter_stmt))
                    db.session.commit()
                    print(f"✅ Added column to devices: {col_name}")
                except Exception as e:
                    print(f"⚠️ Device column {col_name} - {str(e)[:50]}")
                    db.session.rollback()
            
            # Add columns to user_sessions table
            session_columns = [
                ('session_hwid_hash', "ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS session_hwid_hash VARCHAR(256)"),
                ('session_hardware_fingerprint', "ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS session_hardware_fingerprint VARCHAR(256)"),
                ('session_pc_manufacturer', "ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS session_pc_manufacturer VARCHAR(200)"),
                ('session_windows_version', "ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS session_windows_version VARCHAR(100)"),
            ]
            
            for col_name, alter_stmt in session_columns:
                try:
                    db.session.execute(text(alter_stmt))
                    db.session.commit()
                    print(f"✅ Added column to user_sessions: {col_name}")
                except Exception as e:
                    print(f"⚠️ Session column {col_name} - {str(e)[:50]}")
                    db.session.rollback()
                    
            print("✅ Device binding columns migration completed")
            
        except Exception as e:
            print(f"❌ Error adding device binding columns: {e}")
            # Don't crash the app if migration fails
          
  # ========== ADD THIS LINE RIGHT HERE ==========
        add_security_columns()


        
        
    # ==================== ADMIN USER SETUP FROM ENV ====================
        admin_email = os.environ.get('ADMIN_EMAIL')
        admin_password = os.environ.get('ADMIN_PASSWORD')
        
        if admin_email and admin_password:
            admin = User.query.filter_by(email=admin_email).first()
            if not admin:
                admin = User(
                    username='admin',
                    email=admin_email,
                    admission_number=1000,
                    credits=10,
                    is_admin=True,
                    is_active=True,
                    device_limit=0,
                    license_expiry_date=datetime.utcnow() + timedelta(days=3650)  # 10 years
                )
                admin.set_password(admin_password)
                db.session.add(admin)
                db.session.commit()
                print(f"✅ Admin user created: {admin_email}")
            else:
                if not admin.is_admin:
                    admin.is_admin = True
                    db.session.commit()
                    print("✅ Updated existing user to admin")
                
                if admin.credits is None or admin.credits == 0:
                    admin.credits = 1000
                    db.session.commit()
                    print("✅ Added credits to admin")
                
                # Update password if env password is different
                if not admin.check_password(admin_password):
                    admin.set_password(admin_password)
                    db.session.commit()
                    print("✅ Updated admin password from environment")
        else:
            print("⚠️ ADMIN_EMAIL and ADMIN_PASSWORD not set in environment variables")
            print("   Set them in Render dashboard to secure your admin account")
    
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = None

        # ==================== MAINTENANCE MODE ====================
    
    MAINTENANCE_FILE = os.path.join(BASE_DIR, 'maintenance.json')
    
    def is_maintenance_mode():
        try:
            if os.path.exists(MAINTENANCE_FILE):
                with open(MAINTENANCE_FILE, 'r') as f:
                    return json.load(f).get('maintenance', False)
        except:
            pass
        return False
    
    def set_maintenance(enabled, msg="Server under maintenance. Please check back later. Thank you for your patience."):
        with open(MAINTENANCE_FILE, 'w') as f:
            json.dump({'maintenance': enabled, 'message': msg}, f)
    
    @app.before_request
    def check_maintenance():
        if is_maintenance_mode():
            if request.path.startswith('/login') or \
               request.path.startswith('/api/admin') or \
               request.path.startswith('/admin-dashboard') or \
               request.path.startswith('/static') or \
               request.path.startswith('/health') or \
               request.path.startswith('/logout') or \
               request.path.startswith('/favicon.ico'):
                if current_user.is_authenticated and current_user.is_admin:
                    return None
            if request.path.startswith('/api/'):
                return jsonify({
                    'success': False, 
                    'error': 'Server under maintenance. Please check back later. Thank you for your patience.',
                    'code': 'MAINTENANCE_MODE',
                    'maintenance': True
                }), 503
            if 'text/html' in request.headers.get('Accept', ''):
                return render_template('maintanance.html'), 503
    
    @app.route('/api/admin/toggle-maintenance', methods=['POST'])
    @login_required
    def toggle_maintenance():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        data = request.get_json()
        enabled = data.get('enabled', True)
        set_maintenance(enabled)
        status = 'ON' if enabled else 'OFF'
        log_system_action(current_user.id, 'maintenance', f'Maintenance turned {status}')
        return jsonify({'success': True, 'maintenance': enabled, 'status': f'Maintenance is {status}'})
    
    @app.route('/api/admin/maintenance-status')
    @login_required
    def maintenance_status():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        return jsonify({'maintenance': is_maintenance_mode()})
    
    # ==================== API AUTH DECORATOR ====================
    def api_login_required(f):
        """Decorator for API endpoints that returns JSON for unauthenticated requests"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # First check if user is authenticated via Flask-Login (web session)
            if current_user.is_authenticated:
                return f(*args, **kwargs)
            
            # Then try to get user from token (desktop client)
            user = get_user_from_token()
            if user:
                login_user(user, remember=False)
                return f(*args, **kwargs)
            
            # Return JSON error for API requests instead of redirect
            return jsonify({'success': False, 'error': 'Unauthorized', 'message': 'Please login first'}), 401
        return decorated_function
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # ==================== HELPER FUNCTIONS ====================
    def get_next_admission_number():
        last_user = User.query.order_by(User.admission_number.desc()).first()
        if last_user and last_user.admission_number:
            return last_user.admission_number + 1
        return 1000
    
    def log_system_action(user_id, action_type, message, ip=None):
        try:
            log = SystemLog(
                user_id=user_id,
                log_type=action_type,
                message=message,
                ip_address=ip or get_real_ip(),
                user_agent=request.headers.get('User-Agent')[:500] if request.headers.get('User-Agent') else None
            )
            db.session.add(log)
            db.session.commit()
        except Exception as e:
            print(f"Error logging system action: {e}")
            db.session.rollback()
    
    def log_device_history(user_id, action, device_id=None, device_name=None, reason=None):
        try:
            history = DeviceHistory(
                user_id=user_id,
                device_id=device_id,
                device_name=device_name,
                action=action,
                reason=reason,
                ip_address=get_real_ip(),
                user_agent=request.headers.get('User-Agent')[:500] if request.headers.get('User-Agent') else None
            )
            db.session.add(history)
            db.session.commit()
        except Exception as e:
            print(f"Error logging device history: {e}")
            db.session.rollback()
    
    def send_reset_email(email, reset_token):
        """Send password reset email to user"""
        try:
            config = app.config
            smtp_server = config.get('SMTP_SERVER', 'smtp.gmail.com')
            smtp_port = config.get('SMTP_PORT', 587)
            smtp_user = config.get('SMTP_USER')
            smtp_password = config.get('SMTP_PASSWORD')
            from_email = config.get('FROM_EMAIL', smtp_user)
            app_name = config.get('APP_NAME', 'Dolphin Bypass Tool')
            
            # ✅ Get correct BASE_URL from environment
            base_url = os.environ.get('BASE_URL') or config.get('BASE_URL') or 'https://my-dolphin-tool-02.onrender.com'
            
            print(f"📧 Reset email - Base URL: {base_url}")
            
            print(f"\n{'='*60}")
            print(f"📧 EMAIL CONFIGURATION CHECK:")
            print(f"   SMTP_SERVER: {smtp_server}")
            print(f"   SMTP_PORT: {smtp_port}")
            print(f"   SMTP_USER: {smtp_user}")
            print(f"   SMTP_PASSWORD set: {'YES' if smtp_password else 'NO'}")
            print(f"   FROM_EMAIL: {from_email}")      
            print(f"   BASE_URL: {base_url}")
            print(f"{'='*60}\n")

            reset_link = f"{base_url}/reset-password/{reset_token}"
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Password Reset</title>
                <style>
                    body {{ font-family: Arial, sans-serif; }}
                    .container {{ max-width: 600px; margin: 40px auto; padding: 20px; background: #fff; border-radius: 10px; }}
                    .button {{ display: inline-block; padding: 12px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>Password Reset Request</h2>
                    <p>We received a request to reset your password for <strong>{email}</strong>.</p>
                    <p>Click the button below to reset your password:</p>
                    <div style="text-align: center;">
                        <a href="{reset_link}" class="button">Reset Password</a>
                    </div>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you didn't request this, please ignore this email.</p>
                </div>
            </body>
            </html>
            """
            
            if smtp_user and smtp_password and smtp_user != 'your-email@gmail.com':
                msg = MIMEMultipart('alternative')
                msg['Subject'] = f"Password Reset - {app_name}"
                msg['From'] = from_email
                msg['To'] = email
                msg.attach(MIMEText(html_content, 'html'))
                
                server = smtplib.SMTP(smtp_server, smtp_port)
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
                server.quit()
                print(f"✅ Password reset email sent to {email}")
                return True
            else:
                print(f"\n{'='*60}")
                print(f"📧 PASSWORD RESET LINK (Email not configured)")
                print(f"Reset Link: {reset_link}")
                print(f"{'='*60}\n")
                return True
        except Exception as e:
            print(f"❌ Failed to send reset email: {e}")
            return False

            

            # ==================== ADD THESE TWO FUNCTIONS RIGHT HERE ====================
    
    def send_welcome_email_with_credentials(email, username, password, license_type, days, admission_number):
        """Send welcome email with login credentials to newly registered user"""
        try:
            config = app.config
            smtp_server = config.get('SMTP_SERVER', 'smtp.gmail.com')
            smtp_port = config.get('SMTP_PORT', 587)
            smtp_user = config.get('SMTP_USER')
            smtp_password = config.get('SMTP_PASSWORD')
            from_email = config.get('FROM_EMAIL', smtp_user)
            app_name = config.get('APP_NAME', 'Dolphin Bypass Tool')
            
            base_url = os.environ.get('BASE_URL') or config.get('BASE_URL') or 'https://my-dolphin-tool-02.onrender.com'
            
            # Device limits for display
            device_limits_display = {
                '12hr': 1,
                '3_months': 10,
                '6_months': 20,
                '1_year': 45
            }
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Welcome to {app_name}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; background: #f9f9f9; }}
                    .header {{ background: #667eea; color: white; padding: 20px; text-align: center; }}
                    .content {{ padding: 20px; background: white; }}
                    .credentials {{ background: #f0f0f0; padding: 15px; margin: 15px 0; font-family: monospace; }}
                    .footer {{ text-align: center; padding: 20px; font-size: 12px; color: #666; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2>Welcome to {app_name}</h2>
                    </div>
                    <div class="content">
                        <h3>Your account has been created!</h3>
                        <p>Dear <strong>{username}</strong>,</p>
                        <p>A {license_type} license has been activated for you by a reseller.</p>
                        
                        <div class="credentials">
                            <strong>Login Credentials:</strong><br>
                            Email: {email}<br>
                            Username: {username}<br>
                            Admission Number: {admission_number}<br>
                            Password: <strong style="color: #667eea;">{password}</strong><br>
                        </div>
                        
                        <p><strong>License Details:</strong></p>
                        <ul>
                            <li>License Type: {license_type}</li>
                            <li>Duration: {days} days</li>
                            <li>Device Limit: {device_limits_display.get(license_type, 1)} devices</li>
                        </ul>
                        
                        <p><strong>Important:</strong> Please change your password after your first login.</p>
                        
                        <p><a href="{base_url}/login" style="display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px;">Login to Dashboard</a></p>
                        
                        <p>If you have any questions, please contact your reseller or our support team.</p>
                    </div>
                    <div class="footer">
                        <p>{app_name} - Professional Tool for Technicians</p>
                        <p>This email was sent automatically. Please do not reply.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Check if SMTP is configured
            if smtp_user and smtp_password and smtp_user != 'your-email@gmail.com':
                try:
                    # Set timeout to avoid hanging
                    import socket
                    old_timeout = socket.getdefaulttimeout()
                    socket.setdefaulttimeout(10)
                    
                    msg = MIMEMultipart('alternative')
                    msg['Subject'] = f"Welcome to {app_name} - Your Account Details"
                    msg['From'] = from_email
                    msg['To'] = email
                    msg.attach(MIMEText(html_content, 'html'))
                    
                    server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
                    server.starttls()
                    server.login(smtp_user, smtp_password)
                    server.send_message(msg)
                    server.quit()
                    
                    socket.setdefaulttimeout(old_timeout)
                    print(f"✅ Welcome email sent to {email}")
                    return True
                except Exception as smtp_err:
                    print(f"⚠️ SMTP error for {email}: {smtp_err}")
                    # Fall back to console output
                    print(f"\n{'='*60}")
                    print(f"📧 WELCOME EMAIL (SMTP failed, showing credentials)")
                    print(f"To: {email}")
                    print(f"Username: {username}")
                    print(f"Password: {password}")
                    print(f"Admission: {admission_number}")
                    print(f"License: {license_type} ({days} days)")
                    print(f"{'='*60}\n")
                    return True
            else:
                # Print to console if email not configured
                print(f"\n{'='*60}")
                print(f"📧 WELCOME EMAIL (Email not configured)")
                print(f"To: {email}")
                print(f"Username: {username}")
                print(f"Password: {password}")
                print(f"Admission: {admission_number}")
                print(f"License: {license_type} ({days} days)")
                print(f"{'='*60}\n")
                return True
                
        except Exception as e:
            print(f"❌ Failed to send welcome email to {email}: {e}")
            # Don't crash - just log the error
            return False

    def send_license_activation_email(email, username, license_type, days):
        """Send notification email for license activation to existing user"""
        try:
            config = app.config
            smtp_server = config.get('SMTP_SERVER', 'smtp.gmail.com')
            smtp_port = config.get('SMTP_PORT', 587)
            smtp_user = config.get('SMTP_USER')
            smtp_password = config.get('SMTP_PASSWORD')
            from_email = config.get('FROM_EMAIL', smtp_user)
            app_name = config.get('APP_NAME', 'Dolphin Bypass Tool')
            
            base_url = os.environ.get('BASE_URL') or config.get('BASE_URL') or 'https://my-dolphin-tool-02.onrender.com'
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>License Activated - {app_name}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; background: #f9f9f9; }}
                    .header {{ background: #48bb78; color: white; padding: 20px; text-align: center; }}
                    .content {{ padding: 20px; background: white; }}
                    .footer {{ text-align: center; padding: 20px; font-size: 12px; color: #666; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2>License Activated!</h2>
                    </div>
                    <div class="content">
                        <h3>Hello {username}!</h3>
                        <p>Your {license_type} license has been activated successfully.</p>
                        
                        <p><strong>License Details:</strong></p>
                        <ul>
                            <li>License Type: {license_type}</li>
                            <li>Duration: {days} days</li>
                        </ul>
                        
                        <p>You can now access all features of {app_name}.</p>
                        
                        <p><a href="{base_url}/login" style="display: inline-block; padding: 10px 20px; background: #48bb78; color: white; text-decoration: none; border-radius: 5px;">Login to Dashboard</a></p>
                        
                        <p>Note: Your existing password remains unchanged.</p>
                    </div>
                    <div class="footer">
                        <p>{app_name} - Professional Tool for Technicians</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Check if SMTP is configured
            if smtp_user and smtp_password and smtp_user != 'your-email@gmail.com':
                try:
                    # Set timeout to avoid hanging
                    import socket
                    old_timeout = socket.getdefaulttimeout()
                    socket.setdefaulttimeout(10)
                    
                    msg = MIMEMultipart('alternative')
                    msg['Subject'] = f"License Activated - {app_name}"
                    msg['From'] = from_email
                    msg['To'] = email
                    msg.attach(MIMEText(html_content, 'html'))
                    
                    server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
                    server.starttls()
                    server.login(smtp_user, smtp_password)
                    server.send_message(msg)
                    server.quit()
                    
                    socket.setdefaulttimeout(old_timeout)
                    print(f"✅ License activation email sent to {email}")
                    return True
                except Exception as smtp_err:
                    print(f"⚠️ SMTP error for {email}: {smtp_err}")
                    # Fall back to console output
                    print(f"\n{'='*60}")
                    print(f"📧 LICENSE ACTIVATION (SMTP failed)")
                    print(f"To: {email}")
                    print(f"License: {license_type} ({days} days)")
                    print(f"{'='*60}\n")
                    return True
            else:
                print(f"\n{'='*60}")
                print(f"📧 LICENSE ACTIVATION (Email not configured)")
                print(f"To: {email}")
                print(f"License: {license_type} ({days} days)")
                print(f"{'='*60}\n")
                return True
                
        except Exception as e:
            print(f"❌ Failed to send license email to {email}: {e}")
            # Don't crash - just log the error
            return False

     # ==================== SAMSUNG FRP HELPER FUNCTIONS ====================
    
    def generate_order_id():
        """Generate unique Samsung FRP order ID"""
        import random
        import string
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        random_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        return f"SAM-{timestamp}-{random_str}"
    
    def check_samsung_frp_server():
        """Check if Samsung FRP external server is online"""
        try:
            from database import ServerStatus
            import requests
            
            # Check if manual override is set
            server_status = ServerStatus.query.filter_by(server_name='samsung_frp_server').first()
            
            if server_status and server_status.manual_override:
                return server_status.is_online
            
            # Auto-check the actual server
            response = requests.get(f"{SAMSUNG_FRP_SERVER_URL}/health", timeout=5)
            is_online = response.status_code == 200
            
            # Update database record
            if not server_status:
                server_status = ServerStatus(server_name='samsung_frp_server')
                db.session.add(server_status)
            
            server_status.is_online = is_online
            server_status.last_check = datetime.utcnow()
            server_status.response_time = int(response.elapsed.total_seconds() * 1000) if is_online else 0
            db.session.commit()
            
            return is_online
        except Exception as e:
            # Server is offline or error
            from database import ServerStatus
            server_status = ServerStatus.query.filter_by(server_name='samsung_frp_server').first()
            if server_status and not server_status.manual_override:
                server_status.is_online = False
                server_status.last_check = datetime.utcnow()
                server_status.error_message = str(e)
                db.session.commit()
            return False


                    ######backup################################################################
       
    @app.route('/auth/reset-password/<token>', methods=['GET', 'POST'])
    def auth_reset_password(token):
        if current_user.is_authenticated:
            logout_user()
            flask_session.clear()
        
        user = User.query.filter_by(reset_token=token).first()
        
        if not user or not user.verify_reset_token(token):
            flash('Invalid or expired reset token.', 'danger')
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            password = request.form.get('password', '')[:128]
            confirm = request.form.get('confirm_password', '')[:128]
            
            if password != confirm:
                flash('Passwords do not match.', 'danger')
                return render_template('reset_password.html', token=token)
            
            if len(password) < 6:
                flash('Password must be at least 6 characters.', 'danger')
                return render_template('reset_password.html', token=token)
            
            user.set_password(password)
            user.clear_reset_token()
            db.session.commit()
            
            flash('Password reset successfully! Please login.', 'success')
            return redirect(url_for('login'))
        
        return render_template('reset_password.html', token=token)

##########DESKTOP VALIDATION SPOT #################################################
    
    @app.route('/api/validate-license', methods=['POST'])
    def validate_license():
        db_session = db.session
        try:
            # ========== CHECK MAINTENANCE MODE ==========
            if is_maintenance_mode():
                return jsonify({
                    'success': False,
                    'error': 'Server under maintenance. Please check back later. Thank you for your patience.',
                    'code': 'MAINTENANCE_MODE',
                    'maintenance': True
                }), 503
            
            data = request.get_json()
            
            if not data:
                return jsonify({'success': False, 'error': 'No JSON data received'}), 400
            
            if not data.get('password'):
                return jsonify({'success': False, 'error': 'Password required'}), 400
            
            email = data.get('email', '').strip()[:100] if data.get('email') else None
            username = data.get('username', '').strip()[:80] if data.get('username') else None
            admission = data.get('admission', '').strip()[:20] if data.get('admission') else None
            admission_number = data.get('admission_number')
            password = data.get('password', '')[:128]
            hwid = data.get('hwid', '')[:256] if data.get('hwid') else None
            
            # ========== EXTRACT DEVICE BINDING INFORMATION ==========
            pc_manufacturer = data.get('pc_manufacturer', '').strip()[:200]
            windows_version = data.get('windows_version', '').strip()[:100]
            hardware_fingerprint = data.get('hardware_fingerprint', '').strip()[:256]
            system_info = data.get('system_info', {})
            tool_version = data.get('tool_version', '').strip()[:20]
            
            # Debug print
            print(f"\n🔐 [LOGIN] Device Binding Info - PC: {pc_manufacturer}, OS: {windows_version[:50] if windows_version else 'Unknown'}...")
            
            # Get IP for rate limiting
            client_ip = get_real_ip()
            
            # Identify unique identifier for rate limiting
            identifier = email or username or admission or str(admission_number) or client_ip
            
            # CHECK LOGIN RATE LIMIT (10 attempts per hour)
            allowed, wait_seconds, suspended_until = check_login_limit(identifier, client_ip, max_attempts=10, window_hours=1)
            
            if not allowed:
                wait_minutes = int(wait_seconds // 60)
                wait_seconds_remain = int(wait_seconds % 60)
                
                return jsonify({
                    'success': False,
                    'error': 'Account suspended for 1 hour due to too many failed login attempts.',
                    'code': 'ACCOUNT_SUSPENDED',
                    'message': f'Your account has been temporarily suspended. Please wait {wait_minutes} minutes and {wait_seconds_remain} seconds before trying again.',
                    'suspended_until': suspended_until.isoformat() if suspended_until else None,
                    'remaining_seconds': wait_seconds,
                    'remaining_minutes': wait_minutes,
                    'retry_after': wait_seconds
                }), 403
            
            # Find user
            user = None
            if email:
                user = User.query.filter_by(email=email).first()
            elif username:
                user = User.query.filter_by(username=username).first()
            elif admission:
                if admission.isdigit():
                    user = User.query.filter_by(admission_number=int(admission)).first()
            elif admission_number:
                if str(admission_number).isdigit():
                    user = User.query.filter_by(admission_number=int(admission_number)).first()
            
            if not user:
                log_login_attempt(identifier, False, client_ip, user_id=None)
                return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
            
            if not user.check_password(password):
                log_login_attempt(identifier, False, client_ip, user_id=user.id)
                return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
            
            # SUCCESSFUL LOGIN - clear rate limit records
            log_login_attempt(identifier, True, client_ip, user_id=user.id)
            
            # Clear suspension on successful login
            if user.suspended_until:
                user.suspended_until = None
                user.failed_login_count = 0
                db_session.commit()
                print(f"✅ Suspension cleared for user {user.username}")
            
            # Delete old failed attempts on successful login
            LoginAttempt.query.filter(
                LoginAttempt.identifier == identifier,
                LoginAttempt.attempt_type == 'login',
                LoginAttempt.success == False,
                LoginAttempt.attempt_time < datetime.utcnow() - timedelta(hours=1)
            ).delete()
            db_session.commit()
            
            if user.is_banned:
                return jsonify({'success': False, 'error': 'Account is banned', 'is_banned': True}), 403
            
            if not user.is_license_valid():
                return jsonify({
                    'success': False, 
                    'error': 'License has expired. Please renew your license.',
                    'license_expired': True,
                    'license_expiry': user.license_expiry_date.isoformat() if user.license_expiry_date else None
                }), 403
            
            # ========== HWID CHECK - PREVENT SAME HWID ON MULTIPLE ACCOUNTS ==========
            device_registered = False
            device_id = None
            device_name = None
            hashed_hwid = hash_hwid(hwid) if hwid else None
            session_obj = None
            
            if hashed_hwid:
                # CRITICAL: Check if this HWID is already bound to ANY active account
                existing_device = Device.query.filter_by(hwid_hash=hashed_hwid).first()
                
                if existing_device:
                    # HWID exists - check if it belongs to THIS user
                    if existing_device.user_id == user.id:
                        # Same user - allowed, reactivate if needed
                        device_registered = True
                        device_id = existing_device.id
                        device_name = existing_device.device_name
                        
                        if not existing_device.is_active:
                            existing_device.is_active = True
                            existing_device.last_seen = datetime.utcnow()
                            existing_device.ip_address = get_real_ip()
                            db_session.add(existing_device)
                            log_device_history(user.id, 'reactivate', device_id, device_name, 'Device reactivated')
                        
                        # Check for existing active session
                        session_obj = UserSession.query.filter_by(
                            device_id=device_id,
                            is_active=True
                        ).filter(UserSession.expires_at > datetime.utcnow()).first()
                        
                        if not session_obj:
                            session_obj = UserSession(
                                user_id=user.id,
                                device_id=device_id,
                                session_token=secrets.token_urlsafe(32),
                                ip_address=get_real_ip(),
                                user_agent=request.headers.get('User-Agent')[:500] if request.headers.get('User-Agent') else None,
                                expires_at=datetime.utcnow() + timedelta(hours=SESSION_DURATION_HOURS),
                                is_active=True
                            )
                            db_session.add(session_obj)
                        
                        log_device_history(user.id, 'login', device_id, device_name, 'Desktop client login')
                    else:
                        # HWID belongs to DIFFERENT user - BLOCK
                        other_user = User.query.get(existing_device.user_id)
                        return jsonify({
                            'success': False, 
                            'error': f'This hardware is already bound to another account ({other_user.username if other_user else "unknown"}). HWID cannot be used on multiple accounts.',
                            'code': 'HWID_ALREADY_BOUND',
                            'bound_to': other_user.username if other_user else None
                        }), 403
                else:
                    # New HWID - check device limit for this user
                    active_count = Device.query.filter_by(user_id=user.id, is_active=True).count()
                    if active_count >= user.device_limit:
                        return jsonify({
                            'success': False,
                            'error': f'Device limit reached ({active_count}/{user.device_limit} devices)',
                            'code': 'DEVICE_LIMIT_REACHED',
                            'requires_reset': True
                        }), 403
                    
                    # Register new device
                    new_device = Device(
                        user_id=user.id,
                        hardware_id=hwid,
                        hwid_hash=hashed_hwid,
                        device_name=f"Desktop-{hwid[:8]}" if hwid else "Unknown-Device",
                        ip_address=get_real_ip(),
                        is_active=True,
                        is_bound=True,
                        pc_manufacturer=pc_manufacturer if pc_manufacturer else None,
                        windows_version=windows_version if windows_version else None,
                        hardware_fingerprint=hardware_fingerprint if hardware_fingerprint else None
                    )
                    db_session.add(new_device)
                    db_session.flush()
                    device_id = new_device.id
                    device_name = new_device.device_name
                    device_registered = True
                    
                    session_obj = UserSession(
                        user_id=user.id,
                        device_id=device_id,
                        session_token=secrets.token_urlsafe(32),
                        ip_address=get_real_ip(),
                        user_agent=request.headers.get('User-Agent')[:500] if request.headers.get('User-Agent') else None,
                        expires_at=datetime.utcnow() + timedelta(hours=SESSION_DURATION_HOURS),
                        is_active=True
                    )
                    db_session.add(session_obj)
                    
                    user.total_devices_registered = (user.total_devices_registered or 0) + 1
                    
                    log_device_history(user.id, 'register', device_id, device_name, 'Desktop client registered')
                    log_system_action(user.id, 'device_register', f'New desktop client registered: {device_name}')
                    print(f"✅ New device registered: {device_name} for user {user.username}")
            
            # ========== STORE DEVICE BINDING INFORMATION ==========
            # Store device binding information on successful login
            if pc_manufacturer or windows_version or hardware_fingerprint:
                # Check if this is first time binding (no bound HWID yet)
                if not user.bound_hwid_hash and hashed_hwid:
                    # First time binding - store all device info
                    user.bound_hwid_hash = hashed_hwid
                    user.bound_pc_manufacturer = pc_manufacturer
                    user.bound_windows_version = windows_version
                    user.bound_hardware_fingerprint = hardware_fingerprint
                    user.bound_system_info = json.dumps(system_info) if system_info else None
                    user.bound_ip_address = client_ip
                    user.bound_at = datetime.utcnow()
                    user.last_verified_at = datetime.utcnow()
                    user.is_verified_device = True
                    user.verification_failures = 0
                    db_session.commit()
                    print(f"✅✅✅ Device bound to user {user.username} - Manufacturer: {pc_manufacturer}")
                    log_system_action(user.id, 'device_bound', 
                                    f'Device bound - Manufacturer: {pc_manufacturer}, OS: {windows_version[:50] if windows_version else "Unknown"}')
                elif hashed_hwid and hashed_hwid == user.bound_hwid_hash:
                    # Existing device - update last verified timestamp
                    user.last_verified_at = datetime.utcnow()
                    db_session.commit()
                    print(f"✅ Device verified for user {user.username}")
                elif hashed_hwid and hashed_hwid != user.bound_hwid_hash and user.bound_hwid_hash:
                    # Device mismatch - increment failure counter
                    user.verification_failures = (user.verification_failures or 0) + 1
                    db_session.commit()
                    log_system_action(user.id, 'device_mismatch', 
                                    f'Device mismatch - Bound HWID: {user.bound_hwid_hash[:16] if user.bound_hwid_hash else "None"}..., Current: {hashed_hwid[:16]}...')
                    print(f"⚠️ Device mismatch for user {user.username} - Attempt {user.verification_failures}/3")
                    
                    if user.verification_failures >= 3:
                        user.suspended_until = datetime.utcnow() + timedelta(hours=24)
                        db_session.commit()
                        return jsonify({
                            'success': False,
                            'error': 'Device mismatch detected. Account suspended for 24 hours.',
                            'code': 'DEVICE_MISMATCH_SUSPENDED'
                        }), 403
            
            # Create session if not exists
            if not session_obj:
                session_obj = UserSession(
                    user_id=user.id,
                    device_id=None,
                    session_token=secrets.token_urlsafe(32),
                    ip_address=get_real_ip(),
                    user_agent=request.headers.get('User-Agent')[:500] if request.headers.get('User-Agent') else None,
                    expires_at=datetime.utcnow() + timedelta(hours=SESSION_DURATION_HOURS),
                    is_active=True
                )
                db_session.add(session_obj)
            
            db_session.commit()
            
            session_key = session_obj.session_token
            flask_session['module_key'] = session_key
            user.current_session_key = session_key
            db_session.commit()
            
            print(f"🔑 Session key saved: {session_key[:20]}...")
            
            device_count = Device.query.filter_by(user_id=user.id, is_active=True).count()
            
            days_remaining = 0
            if user.license_expiry_date:
                days_remaining = (user.license_expiry_date - datetime.utcnow()).days
                if days_remaining < 0:
                    days_remaining = 0

            # Update last login
            user.last_login = datetime.utcnow()
            db_session.commit()
            
            response_data = {
                'success': True,
                'user_id': user.id,
                'username': user.username,
                'email': user.email,
                'admission_number': user.admission_number,
                'license_type': user.license_type,
                'license_status': 'active' if user.is_license_valid() else 'expired',
                'license_expiry': user.license_expiry_date.isoformat() if user.license_expiry_date else None,
                'days_remaining': days_remaining,
                'device_limit': user.device_limit,
                'device_count': device_count,
                'credits': user.credits or 0,
                'is_admin': user.is_admin,
                'is_reseller': user.is_reseller,
                'is_banned': user.is_banned,
                'license_valid': user.is_license_valid(),
                'session_key': session_key,
                'device_registered': device_registered,
                'device_id': device_id,
                'device_name': device_name,
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'suspended_until': user.suspended_until.isoformat() if user.suspended_until else None
            }
            
            import base64
            temp_key = hashlib.sha256(password.encode()).digest()
            json_str = json.dumps(response_data, ensure_ascii=False)
            json_bytes = json_str.encode('utf-8')
            encrypted = bytes([b ^ temp_key[i % len(temp_key)] for i, b in enumerate(json_bytes)])
            return jsonify({'encrypted': True, 'data': base64.b64encode(encrypted).decode('utf-8')}), 200
            
        except Exception as e:
            db_session.rollback()
            print(f"[ERROR] Validate license error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500
            
        ############################# ##SESSION VALIDATION
    @app.route('/api/user/validate-session', methods=['POST'])
    def validate_session_endpoint():
        try:
            # ========== CHECK MAINTENANCE MODE ==========
            if is_maintenance_mode():
                return jsonify({
                    'success': False,
                    'error': 'Server under maintenance. Please check back later. Thank you for your patience.',
                    'code': 'MAINTENANCE_MODE',
                    'maintenance': True
                }), 503
            
            data = request.get_json() or {}
            session_token = data.get('session_token', '')[:256]
            hwid = data.get('hwid', '')[:256] if data.get('hwid') else None
            hardware_fingerprint = data.get('hardware_fingerprint', '')[:256] if data.get('hardware_fingerprint') else None
            pc_manufacturer = data.get('pc_manufacturer', '')[:200] if data.get('pc_manufacturer') else None
            windows_version = data.get('windows_version', '')[:100] if data.get('windows_version') else None
            
            if not session_token:
                return jsonify({'success': False, 'error': 'Session token required'}), 400
            
            session_obj = UserSession.query.filter_by(
                session_token=session_token,
                is_active=True
            ).filter(UserSession.expires_at > datetime.utcnow()).first()
            
            if not session_obj:
                return jsonify({'success': False, 'valid': False, 'error': 'Invalid or expired session'}), 401
            
            # ========== CHECK INACTIVITY (30 minutes) ==========
            if session_obj.last_activity:
                inactive_seconds = (datetime.utcnow() - session_obj.last_activity).total_seconds()
                if inactive_seconds > (SESSION_INACTIVITY_MINUTES * 60):
                    session_obj.is_active = False
                    db.session.commit()
                    return jsonify({
                        'success': False, 
                        'valid': False, 
                        'error': 'Session expired due to inactivity (30 min)',
                        'code': 'INACTIVITY_TIMEOUT'
                    }), 401
            
            # Get the user associated with this session
            user = User.query.get(session_obj.user_id)
            if not user:
                return jsonify({'success': False, 'valid': False, 'error': 'User not found'}), 401
            
            # ========== DEVICE BINDING VERIFICATION ==========
            verification_warning = None
            
            if hwid:
                hashed_hwid = hash_hwid(hwid)
                device = db.session.get(Device, session_obj.device_id)
                
                # Check if device matches session
                if not device or device.hwid_hash != hashed_hwid:
                    return jsonify({'success': False, 'valid': False, 'error': 'Session does not match device'}), 403
                
                # Check if device matches user's bound HWID (if bound)
                if user.bound_hwid_hash and hashed_hwid != user.bound_hwid_hash:
                    # Device mismatch - increment failure counter
                    user.verification_failures = (user.verification_failures or 0) + 1
                    db.session.commit()
                    log_system_action(user.id, 'session_device_mismatch', 
                                    f'Device mismatch during session validation - Bound: {user.bound_hwid_hash[:16]}..., Current: {hashed_hwid[:16]}...')
                    print(f"⚠️ Session device mismatch for user {user.username} - Attempt {user.verification_failures}/3")
                    
                    if user.verification_failures >= 3:
                        user.suspended_until = datetime.utcnow() + timedelta(hours=24)
                        db.session.commit()
                        return jsonify({
                            'success': False,
                            'valid': False,
                            'error': 'Device mismatch detected. Account suspended for 24 hours.',
                            'code': 'DEVICE_MISMATCH_SUSPENDED'
                        }), 403
                    
                    verification_warning = f"Device mismatch warning - {3 - user.verification_failures} attempts remaining"
                
                # Optional: Check hardware fingerprint if available and bound
                if hardware_fingerprint and user.bound_hardware_fingerprint:
                    if hardware_fingerprint != user.bound_hardware_fingerprint:
                        log_system_action(user.id, 'fingerprint_mismatch', 
                                        f'Hardware fingerprint mismatch during session validation')
                        verification_warning = "Hardware fingerprint mismatch - Please contact support"
                
                # Update last verification timestamp on successful match
                if user.bound_hwid_hash and hashed_hwid == user.bound_hwid_hash:
                    user.last_verified_at = datetime.utcnow()
                    db.session.commit()
            
            # Update session last activity timestamp
            session_obj.last_activity = datetime.utcnow()
            db.session.commit()
            
            response_data = {
                'success': True,
                'valid': True,
                'user_id': session_obj.user_id,
                'expires_at': session_obj.expires_at.isoformat(),
                'device_id': session_obj.device_id,
                'device_verified': user.is_verified_device if user else False,
                'verification_failures': user.verification_failures if user else 0,
            }
            
            if verification_warning:
                response_data['warning'] = verification_warning
            
            return jsonify(response_data)
            
        except Exception as e:
            db.session.rollback()
            print(f"Error in validate_session_endpoint: {e}")
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500

    # ==================== USER DASHBOARD API ENDPOINTS ====================
    @app.route('/api/user/info')
    @api_login_required
    def user_info():
        try:
            user = current_user
            if not user:
                return jsonify({'success': False, 'error': 'User not authenticated'}), 401
            
            days_remaining = 0
            if user.license_expiry_date:
                days_remaining = (user.license_expiry_date - datetime.utcnow()).days
                if days_remaining < 0:
                    days_remaining = 0
            
            device_count = Device.query.filter_by(user_id=user.id, is_active=True).count()
            
            # Get last login
            last_login = user.last_login.isoformat() if user.last_login else None
            
            return jsonify({
                'success': True,
                # ========== ACCOUNT INFORMATION ==========
                'user_id': user.id,
                'username': user.username,
                'email': user.email,
                'credits': user.credits or 0,
                'admission_number': user.admission_number,
                'country': user.country or 'Not set',
                'is_banned': user.is_banned,
                'is_active': user.is_active,
                'is_admin': user.is_admin,
                'is_reseller': user.is_reseller,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': last_login,
                
                # ========== LICENSE INFORMATION ==========
                'license_type': user.license_type or 'None',
                'license_status': 'Active' if user.is_license_valid() else 'Expired',
                'license_expiry': user.license_expiry_date.isoformat() if user.license_expiry_date else None,
                'days_remaining': days_remaining,
                'device_limit': user.device_limit if user.device_limit < 999999 else 'Unlimited',
                'device_count': device_count,
                'license_key': getattr(user, 'license_key', 'N/A'),
                'commission_rate': user.commission_rate or 0,
                'total_commission': user.total_commission or 0,
                'total_sales': user.total_sales or 0,
                
                # ========== DEVICE BINDING INFORMATION ==========
                'is_device_bound': user.bound_hwid_hash is not None,
                'bound_at': user.bound_at.isoformat() if user.bound_at else None,
                'last_verified': user.last_verified_at.isoformat() if user.last_verified_at else None,
                'pc_manufacturer': user.bound_pc_manufacturer or 'Not bound',
                'windows_version': user.bound_windows_version or 'Not bound',
                'bound_ip': user.bound_ip_address or 'Not bound',
                'verification_failures': user.verification_failures or 0,
                'is_verified_device': user.is_verified_device or False,
                'hardware_fingerprint_preview': (user.bound_hardware_fingerprint[:32] + '...') if user.bound_hardware_fingerprint and len(user.bound_hardware_fingerprint) > 32 else (user.bound_hardware_fingerprint or 'Not bound'),
                'bound_hwid_preview': (user.bound_hwid_hash[:16] + '...') if user.bound_hwid_hash else 'Not bound',
                
                # ========== SESSION INFORMATION ==========
                'session_key': getattr(user, 'current_session_key', None),
                'hwid_change_count': user.hwid_change_count or 0,
                'suspended_until': user.suspended_until.isoformat() if user.suspended_until else None,
            })
        except Exception as e:
            print(f"Error in user_info: {e}")
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/user/profile')
    @api_login_required
    def user_profile():
        try:
            user = current_user
            if not user:
                return jsonify({'success': False, 'error': 'User not authenticated'}), 401
            
            days_remaining = 0
            if user.license_expiry_date:
                days_remaining = (user.license_expiry_date - datetime.utcnow()).days
                if days_remaining < 0:
                    days_remaining = 0
            
            device_count = Device.query.filter_by(user_id=user.id, is_active=True).count()
            
            # Get last login from session if not in user object
            last_login = user.last_login.isoformat() if user.last_login else None
            
            return jsonify({
                'success': True,
                # ========== ACCOUNT INFORMATION ==========
                'username': user.username,
                'email': user.email,
                'credits': user.credits or 0,
                'admission_number': user.admission_number,
                'country': user.country or 'Not specified',
                'is_banned': user.is_banned,
                'is_active': user.is_active,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': last_login,
                'commission_rate': user.commission_rate or 0,
                'total_commission': user.total_commission or 0,
                
                # ========== LICENSE INFORMATION ==========
                'license_type': user.license_type or 'None',
                'license_status': 'Active' if user.is_license_valid() else 'Expired',
                'license_expiry': user.license_expiry_date.isoformat() if user.license_expiry_date else None,
                'days_remaining': days_remaining,
                'device_limit': user.device_limit if user.device_limit < 999999 else 'Unlimited',
                'device_count': device_count,
                'license_key': getattr(user, 'license_key', 'N/A'),
                
                # ========== DEVICE BINDING INFORMATION ==========
                'is_device_bound': user.bound_hwid_hash is not None,
                'bound_at': user.bound_at.isoformat() if user.bound_at else None,
                'last_verified': user.last_verified_at.isoformat() if user.last_verified_at else None,
                'pc_manufacturer': user.bound_pc_manufacturer or 'Not bound',
                'windows_version': user.bound_windows_version or 'Not bound',
                'bound_ip': user.bound_ip_address or 'Not bound',
                'verification_failures': user.verification_failures or 0,
                'is_verified_device': user.is_verified_device or False,
                'hardware_fingerprint': user.bound_hardware_fingerprint if user.bound_hardware_fingerprint else 'Not bound',
                'bound_hwid_preview': user.bound_hwid_hash if user.bound_hwid_hash else 'Not bound',
            })
        except Exception as e:
            print(f"Error in user_profile: {e}")
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/user/devices')
    @api_login_required
    def user_devices():
        try:
            devices = Device.query.filter_by(user_id=current_user.id).order_by(Device.created_at.desc()).all()
            
            devices_data = []
            for d in devices:
                devices_data.append({
                    'id': d.id,
                    'device_name': d.device_name or 'Unknown Device',
                    'hwid': d.hwid_hash[:16] + '...' if d.hwid_hash else 'N/A',
                    'hwid_full': d.hwid_hash if d.hwid_hash else None,  # Full HWID for admin
                    'is_active': d.is_active,
                    'is_trusted': getattr(d, 'is_trusted', False),
                    'is_bound': d.is_bound,
                    'created_at': d.created_at.isoformat() if d.created_at else None,
                    'last_seen': d.last_seen.isoformat() if d.last_seen else None,
                    'first_seen': d.first_seen.isoformat() if d.first_seen else None,
                    'ip_address': d.ip_address,
                    # Extra device details
                    'manufacturer': getattr(d, 'manufacturer', None) or getattr(d, 'pc_manufacturer', None),
                    'model': getattr(d, 'model', None),
                    'os_version': getattr(d, 'os_version', None) or getattr(d, 'windows_version', None),
                    'hardware_fingerprint': getattr(d, 'hardware_fingerprint', None),
                    'hardware_fingerprint_preview': (getattr(d, 'hardware_fingerprint', '')[:16] + '...') if getattr(d, 'hardware_fingerprint', '') else None,
                })
            
            # Get current session device info
            current_session = UserSession.query.filter_by(
                user_id=current_user.id, 
                is_active=True
            ).filter(UserSession.expires_at > datetime.utcnow()).first()
            
            current_device_id = current_session.device_id if current_session else None
            
            return jsonify({
                'success': True,
                'devices': devices_data,
                'total': len(devices_data),
                'active_devices': sum(1 for d in devices if d.is_active),
                'device_limit': current_user.device_limit,
                'remaining_slots': max(0, current_user.device_limit - sum(1 for d in devices if d.is_active)),
                'current_device_id': current_device_id,
                # Device binding status
                'is_device_bound': current_user.bound_hwid_hash is not None,
                'bound_device_preview': (current_user.bound_hwid_hash[:16] + '...') if current_user.bound_hwid_hash else None,
                'verification_failures': current_user.verification_failures or 0,
                'is_verified_device': current_user.is_verified_device or False,
            })
        except Exception as e:
            print(f"Error in user_devices: {e}")
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/user/reset-cost')
    @api_login_required
    def user_reset_cost():
        """Get reset cost information"""
        try:
            user = current_user
            reset_cost = DEVICE_RESET_COST
            user_credits = user.credits or 0
            
            active_devices = Device.query.filter_by(user_id=user.id, is_active=True).all()
            total_devices = len(active_devices)
            total_cost_all = reset_cost * total_devices
            
            devices_list = []
            for device in active_devices:
                devices_list.append({
                    'id': device.id,
                    'name': device.device_name or 'Unknown Device',
                    'hwid_preview': device.hwid_hash[:16] + '...' if device.hwid_hash else 'N/A'
                })
            
            return jsonify({
                'success': True,
                'cost_per_device': reset_cost,
                'total_cost_all': total_cost_all,
                'user_credits': user_credits,
                'total_devices': total_devices,
                'can_reset_single': user_credits >= reset_cost and total_devices > 0,
                'can_reset_all': user_credits >= total_cost_all and total_devices > 0,
                'devices': devices_list
            })
        except Exception as e:
            print(f"Error in user_reset_cost: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/user/reset-devices', methods=['POST'])
    @api_login_required
    def user_reset_devices():
        """Reset one or all devices"""
        try:
            data = request.get_json() or {}
            device_id = data.get('device_id')
            
            user = current_user
            reset_cost = DEVICE_RESET_COST
            
            if not device_id:
                # Reset all devices
                devices = Device.query.filter_by(user_id=user.id, is_active=True).all()
                
                if not devices:
                    return jsonify({'success': False, 'error': 'No active devices to reset'}), 400
                
                total_cost = reset_cost * len(devices)
                
                if (user.credits or 0) < total_cost:
                    return jsonify({'success': False, 'error': f'Insufficient credits. Need {total_cost} credits'}), 400
                
                for device in devices:
                    device.is_active = False
                    device.last_seen = datetime.utcnow()
                    UserSession.query.filter_by(device_id=device.id, is_active=True).update({'is_active': False})
                    log_device_history(user.id, 'reset', device.id, device.device_name, 'Reset all devices')
                
                user.credits = (user.credits or 0) - total_cost
                
                transaction = CreditTransaction(
                    user_id=user.id,
                    amount=-total_cost,
                    transaction_type='device_reset',
                    description=f'Reset all {len(devices)} devices'
                )
                db.session.add(transaction)
                db.session.commit()
                
                log_system_action(user.id, 'hwid_reset', f'Reset all {len(devices)} devices')
                
                return jsonify({'success': True, 'message': f'Successfully reset {len(devices)} devices'})
            
            else:
                # Reset single device
                device = Device.query.filter_by(id=device_id, user_id=user.id).first()
                
                if not device:
                    return jsonify({'success': False, 'error': 'Device not found'}), 404
                
                if (user.credits or 0) < reset_cost:
                    return jsonify({'success': False, 'error': f'Insufficient credits. Need {reset_cost} credits'}), 400
                
                device.is_active = False
                device.last_seen = datetime.utcnow()
                UserSession.query.filter_by(device_id=device.id, is_active=True).update({'is_active': False})
                user.credits = (user.credits or 0) - reset_cost
                
                transaction = CreditTransaction(
                    user_id=user.id,
                    amount=-reset_cost,
                    transaction_type='device_reset',
                    description=f'Reset device: {device.device_name}'
                )
                db.session.add(transaction)
                db.session.commit()
                
                log_system_action(user.id, 'hwid_reset', f'Reset device: {device.device_name}')
                log_device_history(user.id, 'reset', device.id, device.device_name, 'HWID reset')
                
                return jsonify({'success': True, 'message': f'Device "{device.device_name}" reset successfully'})
        except Exception as e:
            db.session.rollback()
            print(f"Error in user_reset_devices: {e}")
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/user/device-history')
    @api_login_required
    def user_device_history():
        """Get device history/logs with binding events and detailed information"""
        try:
            # Get device history records
            history = DeviceHistory.query.filter_by(user_id=current_user.id).order_by(DeviceHistory.created_at.desc()).limit(100).all()
            
            history_list = []
            for h in history:
                entry = {
                    'id': h.id,
                    'action': h.action,
                    'reason': h.reason,
                    'device_name': h.device_name,
                    'created_at': h.created_at.isoformat() if h.created_at else None,
                    'ip_address': h.ip_address,
                    'user_agent': h.user_agent[:100] if h.user_agent else None,
                    'extra_data': h.extra_data,
                }
                
                # Add HWID preview if available
                if h.hwid_hash:
                    entry['hwid_preview'] = h.hwid_hash[:16] + '...'
                
                history_list.append(entry)
            
            # If no device history, get system logs as fallback
            if not history_list:
                logs = SystemLog.query.filter_by(user_id=current_user.id).order_by(SystemLog.created_at.desc()).limit(100).all()
                for log in logs:
                    history_list.append({
                        'id': log.id,
                        'action': log.log_type,
                        'reason': log.message,
                        'device_name': None,
                        'created_at': log.created_at.isoformat() if log.created_at else None,
                        'ip_address': log.ip_address,
                        'user_agent': log.user_agent[:100] if log.user_agent else None,
                        'extra_data': None,
                    })
            
            # Get binding events specifically
            binding_events = []
            if current_user.bound_at:
                binding_events.append({
                    'event': 'device_bound',
                    'timestamp': current_user.bound_at.isoformat() if current_user.bound_at else None,
                    'pc_manufacturer': current_user.bound_pc_manufacturer,
                    'windows_version': current_user.bound_windows_version,
                    'ip_address': current_user.bound_ip_address,
                })
            
            if current_user.last_verified_at:
                binding_events.append({
                    'event': 'last_verified',
                    'timestamp': current_user.last_verified_at.isoformat() if current_user.last_verified_at else None,
                    'verification_failures': current_user.verification_failures or 0,
                })
            
            # Get statistics
            stats = {
                'total_history_entries': len(history_list),
                'device_bound': current_user.bound_hwid_hash is not None,
                'bound_at': current_user.bound_at.isoformat() if current_user.bound_at else None,
                'last_verified': current_user.last_verified_at.isoformat() if current_user.last_verified_at else None,
                'verification_failures': current_user.verification_failures or 0,
                'is_verified_device': current_user.is_verified_device or False,
                'total_devices_registered': current_user.total_devices_registered or 0,
                'last_login': current_user.last_login.isoformat() if current_user.last_login else None,
            }
            
            # Group history by action type
            action_counts = {}
            for entry in history_list:
                action = entry.get('action', 'unknown')
                action_counts[action] = action_counts.get(action, 0) + 1
            
            return jsonify({
                'success': True,
                'history': history_list,
                'total': len(history_list),
                'binding_events': binding_events,
                'stats': stats,
                'action_summary': action_counts,
            })
        except Exception as e:
            print(f"Error in user_device_history: {e}")
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500
            
    
    @app.route('/api/user/change-password', methods=['POST'])
    @api_login_required
    def user_change_password():
        try:
            data = request.get_json()
            current_password = data.get('current_password')
            new_password = data.get('new_password')
            
            if not current_password or not new_password:
                return jsonify({'success': False, 'error': 'All fields are required'}), 400
            
            if len(new_password) < 6:
                return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
            
            user = current_user
            
            if not user.check_password(current_password):
                return jsonify({'success': False, 'error': 'Current password is incorrect'}), 401
            
            user.set_password(new_password)
            db.session.commit()
            
            log_system_action(user.id, 'password_change', 'User changed password')
            
            return jsonify({'success': True, 'message': 'Password changed successfully'})
        except Exception as e:
            db.session.rollback()
            print(f"Error in user_change_password: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/user/activity-logs')
    @api_login_required
    def user_activity_logs():
        try:
            logs = SystemLog.query.filter_by(user_id=current_user.id).order_by(SystemLog.created_at.desc()).limit(50).all()
            
            logs_data = []
            for log in logs:
                logs_data.append({
                    'type': log.log_type,
                    'activity': log.message,
                    'time': log.created_at.strftime('%Y-%m-%d %H:%M:%S') if log.created_at else None,
                    'ip': log.ip_address
                })
            
            return jsonify({
                'success': True,
                'logs': logs_data,
                'total': len(logs_data)
            })
        except Exception as e:
            print(f"Error in user_activity_logs: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    # ==================== DETAILED LOG ENDPOINT ====================
    
    @app.route('/api/log-detailed', methods=['POST'])
    @api_login_required
    def log_detailed():
        """Log detailed step information for activity display"""
        try:
            data = request.get_json()
            
            session_token = data.get('session_token')
            tab = data.get('tab', '')
            mode = data.get('mode', '')
            action = data.get('action', '')
            step_type = data.get('step_type', 'info')
            message = data.get('message', '')
            percent = data.get('percent')
            
            user = current_user
            
            # Map step type to better display format
            type_display = {
                'info': 'ℹ️ Info',
                'success': '✅ Success',
                'error': '❌ Error',
                'warning': '⚠️ Warning',
                'progress': '⏳ Progress',
                'device': '📱 Device',
                'scan': '🔍 Scan',
                'connection': '🔌 Connection'
            }
            
            display_type = type_display.get(step_type, '📝 Step')
            
            # Clean the message - remove emojis if already present to avoid duplication
            clean_message = message
            if message.startswith(('✅', '❌', 'ℹ️', '⚠️', '⏳', '📱', '🔌', '🔍', '⚙️', '💎', '━')):
                # Message already has emoji, use as is
                pass
            else:
                # Add appropriate emoji based on type
                emoji_map = {
                    'info': 'ℹ️',
                    'success': '✅',
                    'error': '❌',
                    'warning': '⚠️',
                    'progress': '⏳',
                    'device': '📱',
                    'scan': '🔍',
                    'connection': '🔌'
                }
                emoji = emoji_map.get(step_type, '📝')
                clean_message = f"{emoji} {message}"
            
            # Log to system
            log_system_action(user.id, f'cmd_{step_type}', 
                             f"[{tab}.{mode}.{action}] {clean_message}")
            
            return jsonify({'success': True}), 200
            
        except Exception as e:
            print(f"Error in log_detailed: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/user/stats')
    @api_login_required
    def user_stats():
        try:
            user = current_user
            devices = Device.query.filter_by(user_id=user.id, is_active=True).all()
            total_devices = len(devices)
            device_limit = user.device_limit if user.device_limit < 999999 else 999999
            remaining = device_limit - total_devices if user.device_limit < 999999 else 'Unlimited'
            
            return jsonify({
                'success': True,
                'total_devices': total_devices,
                'device_limit': device_limit,
                'remaining_slots': remaining,
                'credits': user.credits or 0
            })
        except Exception as e:
            print(f"Error in user_stats: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
            
    # ==================== WEB ROUTES ====================
    
    @app.route('/')
    def home():
        if current_user.is_authenticated:
            if current_user.is_admin:
                return redirect('/admin-dashboard')
            elif current_user.is_reseller:
                return redirect('/reseller-dashboard')
            else:
                return redirect('/user-dashboard')
        return render_template('home.html')
    
    @app.route('/admin-dashboard')
    @login_required
    def admin_dashboard():
        if not current_user.is_admin:
            flash('Admin access required', 'danger')
            return redirect('/user-dashboard')
        return render_template('admin_dashboard.html', user=current_user)
    
    @app.route('/user-dashboard')
    @login_required
    def user_dashboard():
        if current_user.is_admin:
            return redirect('/admin-dashboard')
        if current_user.is_reseller:
            return redirect('/reseller-dashboard')
        return render_template('user_dashboard.html', user=current_user)
    
    @app.route('/reseller-dashboard')
    @login_required
    def reseller_dashboard():
        if not current_user.is_reseller and not current_user.is_admin:
            flash('Reseller access required', 'danger')
            return redirect('/user-dashboard')
        return render_template('reseller_dashboard.html', user=current_user)
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            if current_user.is_admin:
                return redirect('/admin-dashboard')
            elif current_user.is_reseller:
                return redirect('/reseller-dashboard')
            return redirect('/user-dashboard')
        
        if request.method == 'POST':
            try:
                email = request.form.get('email', '').strip()[:100]
                admission = request.form.get('admission', '').strip()[:20]
                password = request.form.get('password', '')[:128]
                
                user = None
                if email:
                    user = User.query.filter_by(email=email).first()
                if not user and admission and admission.isdigit():
                    user = User.query.filter_by(admission_number=int(admission)).first()
                
                if user and user.check_password(password) and not user.is_banned:
                    flask_session.clear()
                    login_user(user)
                    user.last_login = datetime.utcnow()
                    db.session.commit()
                    log_system_action(user.id, 'login', f'User {user.username} logged in via web')
                    flash('Logged in successfully!', 'success')
                    
                    if user.is_admin:
                        return redirect('/admin-dashboard')
                    elif user.is_reseller:
                        return redirect('/reseller-dashboard')
                    return redirect('/user-dashboard')
                else:
                    flash('Invalid credentials', 'danger')
            except Exception as e:
                db.session.rollback()
                flash('An error occurred', 'danger')
        
        return render_template('login.html')
    
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated:
            return redirect('/user-dashboard')
        
        if request.method == 'POST':
            try:
                username = request.form.get('username', '').strip()[:80]
                email = request.form.get('email', '').strip().lower()[:100]
                country = request.form.get('country', '').strip()[:50]
                password = request.form.get('password', '')[:128]
                confirm = request.form.get('confirm_password', '')[:128]
                
                errors = []
                if User.query.filter_by(username=username).first():
                    errors.append("Username already exists")
                if User.query.filter_by(email=email).first():
                    errors.append("Email already registered")
                if password != confirm:
                    errors.append("Passwords do not match")
                if len(password) < 6:
                    errors.append("Password must be at least 6 characters")
                
                if errors:
                    for error in errors:
                        flash(error, 'danger')
                else:
                    admission_number = get_next_admission_number()
                    user = User(
                        username=username, 
                        email=email, 
                        country=country, 
                        admission_number=admission_number, 
                        credits=0,
                        device_limit=0
                    )
                    user.set_password(password)
                    db.session.add(user)
                    db.session.commit()
                    log_system_action(user.id, 'register', f'New user registered: {username}')
                    flash(f'Registration successful! Your Admission Number is: {admission_number}', 'success')
                    return redirect('/login')
            except Exception as e:
                db.session.rollback()
                flash('An error occurred during registration', 'danger')
        
        return render_template('register.html')
    
    @app.route('/logout')
    @login_required
    def logout():
        if current_user.is_authenticated:
            log_system_action(current_user.id, 'logout', f'User {current_user.username} logged out')
        logout_user()
        flask_session.clear()
        flash('Logged out successfully', 'success')
        return redirect('/login')
    
    @app.route('/forgot-password', methods=['GET', 'POST'])
    def forgot_password():
        if current_user.is_authenticated:
            return redirect('/user-dashboard')
        
        if request.method == 'POST':
            email = request.form.get('email', '').strip()[:100]
            user = User.query.filter_by(email=email).first()
            
            if user:
                reset_token = user.generate_reset_token()
                db.session.commit()
                send_reset_email(email, reset_token)
                flash('Password reset link has been sent to your email.', 'success')
                log_system_action(user.id, 'password_reset_request', f'Password reset requested for {user.username}')
            else:
                flash('If an account exists with that email, a reset link has been sent.', 'info')
            
            return redirect(url_for('login'))
        
        return render_template('forgot_password.html')
                  
    @app.route('/reset-password/<token>', methods=['GET', 'POST'])
    def reset_password(token):
        if current_user.is_authenticated:
            logout_user()
            flask_session.clear()
        
        user = User.query.filter_by(reset_token=token).first()
        
        if not user or not user.verify_reset_token(token):
            flash('Invalid or expired reset token.', 'danger')
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            password = request.form.get('password', '')[:128]
            confirm = request.form.get('confirm_password', '')[:128]
            
            if password != confirm:
                flash('Passwords do not match.', 'danger')
                return render_template('reset_password.html', token=token)
            
            if len(password) < 6:
                flash('Password must be at least 6 characters.', 'danger')
                return render_template('reset_password.html', token=token)
            
            user.set_password(password)
            user.clear_reset_token()
            db.session.commit()
            
            log_system_action(user.id, 'password_reset', 'Password reset via email')
            flash('Password reset successfully! Please login.', 'success')
            return redirect(url_for('login'))
        
        return render_template('reset_password.html', token=token)
    

    
    @app.route('/health')
    def health_check():
        return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})
    
    # ==================== ADMIN API ENDPOINTS ====================
    
    @app.route('/api/admin/dashboard')
    @login_required
    def admin_dashboard_api():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        total_users = User.query.count()
        total_credits = db.session.query(func.sum(User.credits)).scalar() or 0
        banned_users = User.query.filter_by(is_banned=True).count()
        reseller_count = User.query.filter_by(is_reseller=True).count()
        active_devices = Device.query.filter_by(is_active=True).count()
        
        active_licenses = User.query.filter(
            User.license_expiry_date > datetime.utcnow(),
            User.is_banned == False
        ).count()
        
        expired_licenses = User.query.filter(
            User.license_expiry_date <= datetime.utcnow(),
            User.license_expiry_date.isnot(None)
        ).count()
        
        trial_users = User.query.filter(
            User.license_type.in_(['Trial', '12hr', '24hr', '2day', '3day', '7day', 'Custom'])
        ).count()
        
        return jsonify({
            'total_users': total_users,
            'total_credits': total_credits,
            'banned_users': banned_users,
            'total_resellers': reseller_count,
            'active_devices': active_devices,
            'active_licenses': active_licenses,
            'expired_licenses': expired_licenses,
            'trial_users': trial_users,
            'admin_credits': current_user.credits or 0
        })
    
    @app.route('/api/admin/users')
    @login_required
    def admin_users_api():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        filter_type = request.args.get('filter', 'all')
        search = request.args.get('search', '').lower()
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        offset = (page - 1) * limit
        
        query = User.query
        
        if filter_type == 'regular':
            query = query.filter_by(is_admin=False, is_reseller=False)
        elif filter_type == 'resellers':
            query = query.filter_by(is_reseller=True)
        elif filter_type == 'admins':
            query = query.filter_by(is_admin=True)
        elif filter_type == 'banned':
            query = query.filter_by(is_banned=True)
        elif filter_type == 'trial':
            trial_types = ['Trial', '12hr', '24hr', '2day', '3day', '7day', 'Custom']
            query = query.filter(User.license_type.in_(trial_types))
        
        if search:
            query = query.filter(
                or_(
                    User.username.ilike(f'%{search}%'),
                    User.email.ilike(f'%{search}%'),
                    User.admission_number.cast().ilike(f'%{search}%')
                )
            )
        
        total = query.count()
        users = query.offset(offset).limit(limit).all()
        
        users_data = [{
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'admission_number': u.admission_number,
            'license_type': u.license_type or 'None',
            'device_limit': u.device_limit,
            'credits': u.credits or 0,
            'is_admin': u.is_admin,
            'is_reseller': u.is_reseller,
            'is_banned': u.is_banned,
            'created_at': u.created_at.isoformat() if u.created_at else None
        } for u in users]
        
        return jsonify({
            'success': True,
            'users': users_data,
            'total': total,
            'page': page,
            'limit': limit
        })
    
    @app.route('/api/admin/resellers')
    @login_required
    def admin_resellers_api():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        search = request.args.get('search', '').lower()
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        offset = (page - 1) * limit
        
        query = User.query.filter_by(is_reseller=True)
        
        if search:
            query = query.filter(
                or_(
                    User.username.ilike(f'%{search}%'),
                    User.email.ilike(f'%{search}%')
                )
            )
        
        total = query.count()
        resellers = query.offset(offset).limit(limit).all()
        
        resellers_data = [{
            'id': r.id,
            'username': r.username,
            'email': r.email,
            'credits': r.credits or 0,
            'commission_rate': r.commission_rate or 15,
            'client_count': User.query.filter_by(activated_by=r.id).count(),
            'total_sales': r.total_sales or 0,
            'is_banned': r.is_banned
        } for r in resellers]
        
        return jsonify({
            'success': True,
            'resellers': resellers_data,
            'total': total,
            'page': page,
            'limit': limit
        })
    
    @app.route('/api/admin/credit-stats')
    @login_required
    def admin_credit_stats():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        total_credits = db.session.query(func.sum(User.credits)).scalar() or 0
        
        transactions = CreditTransaction.query.order_by(CreditTransaction.created_at.desc()).limit(20).all()
        transactions_data = []
        for t in transactions:
            user = User.query.get(t.user_id)
            transactions_data.append({
                'user': user.username if user else 'Unknown',
                'amount': t.amount,
                'reason': t.description,
                'time': t.created_at.isoformat()
            })
        
        low_credit_users = User.query.filter(User.credits < 50, User.credits > 0, User.is_banned == False).limit(10).all()
        low_credit_data = [{
            'id': u.id,
            'username': u.username,
            'credits': u.credits or 0
        } for u in low_credit_users]
        
        return jsonify({
            'success': True,
            'total_credits': total_credits,
            'admin_credits': current_user.credits or 0,
            'transactions': transactions_data,
            'low_credit_users': low_credit_data
        })
    
    @app.route('/api/admin/add-credits', methods=['POST'])
    @login_required
    def admin_add_credits():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        user_input = data.get('user')
        amount = data.get('amount', 0)
        reason = data.get('reason', 'Admin added credits')
        
        if not user_input or amount <= 0:
            return jsonify({'error': 'Invalid input'}), 400
        
        user = None
        user = User.query.filter_by(email=user_input).first()
        
        if not user and user_input.isdigit():
            user = User.query.filter_by(admission_number=int(user_input)).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        old_credits = user.credits or 0
        user.credits = old_credits + amount
        
        transaction = CreditTransaction(
            user_id=user.id,
            amount=amount,
            transaction_type='admin_add',
            description=reason,
            created_by=current_user.id
        )
        db.session.add(transaction)
        db.session.commit()
        
        log_system_action(current_user.id, 'credit', f'Added {amount} credits to {user.username}')
        
        return jsonify({
            'success': True,
            'message': f'Added {amount} credits to {user.username}',
            'user': user.username,
            'old_balance': old_credits,
            'new_balance': user.credits
        })

               #remove credits
    @app.route('/api/admin/remove-credits', methods=['POST'])
    @login_required
    def admin_remove_credits():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        user_input = data.get('user')
        amount = data.get('amount', 0)
        
        if not user_input or amount <= 0:
            return jsonify({'error': 'Invalid input'}), 400
        
        user = User.query.filter_by(email=user_input).first()
        if not user and user_input.isdigit():
            user = User.query.filter_by(admission_number=int(user_input)).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if (user.credits or 0) < amount:
            return jsonify({'error': 'Insufficient credits'}), 400
        
        user.credits = (user.credits or 0) - amount
        
        transaction = CreditTransaction(
            user_id=user.id,
            amount=-amount,
            transaction_type='admin_deduct',
            description='Admin removed credits',
            created_by=current_user.id
        )
        db.session.add(transaction)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Removed {amount} credits from {user.username}',
            'new_balance': user.credits
        })
    
    @app.route('/api/admin/assign-license', methods=['POST'])
    @login_required
    def admin_assign_license():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        email = data.get('email')
        license_type = data.get('license_type')
        
        if not email or not license_type:
            return jsonify({'error': 'Email and license type required'}), 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        durations = {'Fair': 90, 'Good': 180, 'Excellent': 365}
        device_limits = {'Fair': 10, 'Good': 25, 'Excellent': 55}
        
        duration_days = durations.get(license_type, 90)
        device_limit = device_limits.get(license_type, 10)
        
        user.license_type = license_type
        user.license_expiry_date = datetime.utcnow() + timedelta(days=duration_days)
        user.license_status = 'active'
        user.license_valid = True
        user.device_limit = device_limit
        
        db.session.commit()
        
        log_system_action(current_user.id, 'license', f'Assigned {license_type} license to {user.username}')
        
        return jsonify({'success': True, 'message': f'{license_type} license activated for {email}'})
    
    @app.route('/api/admin/assign-custom-license', methods=['POST'])
    @login_required
    def admin_assign_custom_license():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        email = data.get('email')
        license_type = data.get('license_type')
        duration_value = data.get('duration_value', 12)
        duration_unit = data.get('duration_unit', 'hours')
        device_limit = data.get('device_limit', 1)
        
        if not email or not license_type:
            return jsonify({'error': 'Email and license type required'}), 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if duration_unit == 'hours':
            expiry = datetime.utcnow() + timedelta(hours=duration_value)
        elif duration_unit == 'days':
            expiry = datetime.utcnow() + timedelta(days=duration_value)
        elif duration_unit == 'weeks':
            expiry = datetime.utcnow() + timedelta(weeks=duration_value)
        elif duration_unit == 'months':
            expiry = datetime.utcnow() + timedelta(days=duration_value * 30)
        else:
            expiry = datetime.utcnow() + timedelta(hours=duration_value)
        
        user.license_type = license_type
        user.license_expiry_date = expiry
        user.license_status = 'active'
        user.license_valid = True
        user.device_limit = device_limit if device_limit > 0 else 999999
        
        db.session.commit()
        
        log_system_action(current_user.id, 'license', f'Assigned custom {license_type} license to {user.username}')
        
        return jsonify({'success': True, 'message': f'Custom license activated for {email}'})

        #remove license

    @app.route('/api/admin/remove-license', methods=['POST'])
    @login_required
    def admin_remove_license():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email required'}), 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.license_type = 'None'
        user.license_expiry_date = None
        user.license_status = 'inactive'
        user.license_valid = False
        user.device_limit = 0
        
        db.session.commit()
        
        log_system_action(current_user.id, 'license', f'Removed license from {user.username}')
        
        return jsonify({'success': True, 'message': f'License removed from {user.username}'})
        
    
    @app.route('/api/admin/ban-user/<int:user_id>', methods=['POST'])
    @login_required
    def admin_ban_user(user_id):
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        ban = data.get('ban', True)
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if user.is_admin and user.id != current_user.id:
            return jsonify({'error': 'Cannot ban another admin'}), 403
        
        user.is_banned = ban
        db.session.commit()
        
        action = 'banned' if ban else 'unbanned'
        log_system_action(current_user.id, 'moderation', f'{action} user {user.username}')
        
        return jsonify({'success': True, 'is_banned': user.is_banned})
    
    @app.route('/api/admin/make-reseller/<int:user_id>', methods=['POST'])
    @login_required
    def admin_make_reseller(user_id):
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        commission_rate = data.get('commission_rate', 15)
        activation_limit = data.get('activation_limit', 10)  # ✅ Default 10
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.is_reseller = True
        user.commission_rate = commission_rate
        user.activation_limit = activation_limit
        user.activations_used = 0  # Reset counter
        db.session.commit()
        
        log_system_action(current_user.id, 'reseller', 
                         f'Made {user.username} reseller: {commission_rate}% commission, {activation_limit} activations')
        
        return jsonify({
            'success': True,
            'message': f'{user.username} is now a reseller',
            'activation_limit': activation_limit
        })
    
    @app.route('/api/admin/user-devices/<int:user_id>')
    @login_required
    def admin_user_devices(user_id):
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        devices = Device.query.filter_by(user_id=user_id).order_by(Device.created_at.desc()).all()
        
        devices_data = [{
            'id': d.id,
            'device_name': d.device_name or 'Unknown Device',
            'hwid': d.hwid_hash[:16] + '...' if d.hwid_hash else 'Unknown',
            'is_active': d.is_active,
            'last_seen': d.last_seen.isoformat() if d.last_seen else None,
            'created_at': d.created_at.isoformat() if d.created_at else None
        } for d in devices]
        
        active_count = sum(1 for d in devices if d.is_active)
        
        return jsonify({
            'success': True,
            'username': user.username,
            'email': user.email,
            'device_limit': user.device_limit,
            'total_devices': len(devices),
            'active_devices': active_count,
            'devices': devices_data
        })
    
    @app.route('/api/admin/license-stats')
    @login_required
    def admin_license_stats():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        total_users = User.query.count()
        active_licenses = User.query.filter(
            User.license_expiry_date > datetime.utcnow(),
            User.is_banned == False
        ).count()
        expired_licenses = User.query.filter(
            User.license_expiry_date <= datetime.utcnow(),
            User.license_expiry_date.isnot(None)
        ).count()
        total_credits = db.session.query(func.sum(User.credits)).scalar() or 0
        banned_users = User.query.filter_by(is_banned=True).count()
        
        return jsonify({
            'total_users': total_users,
            'active': active_licenses,
            'expired': expired_licenses,
            'total_credits': total_credits,
            'banned': banned_users,
            'total_devices': Device.query.filter_by(is_active=True).count()
        })
    
    @app.route('/api/admin/system-logs')
    @login_required
    def admin_system_logs():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        logs = SystemLog.query.order_by(SystemLog.created_at.desc()).limit(100).all()
        
        logs_data = []
        for l in logs:
            user = User.query.get(l.user_id) if l.user_id else None
            logs_data.append({
                'type': l.log_type,
                'message': l.message,
                'username': user.username if user else 'System',
                'ip': l.ip_address,
                'created': l.created_at.isoformat()
            })
        
        return jsonify({'success': True, 'logs': logs_data})
    
   
    @app.route('/api/admin/change-user-password', methods=['POST'])
    @login_required
    def admin_change_user_password():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        email = data.get('email')
        new_password = data.get('new_password')
        
        if not email or not new_password:
            return jsonify({'error': 'Email and new password required'}), 400
        
        if len(new_password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.set_password(new_password)
        db.session.commit()
        
        log_system_action(current_user.id, 'admin_password_change', f'Changed password for user {user.username}')
        
        return jsonify({'success': True, 'message': f'Password changed for {user.username}'})


    # ==================== ADMIN RESET LIMITS ENDPOINTS ====================
    @app.route('/api/admin/user-limits/<int:user_id>')
    @login_required
    def admin_get_user_limits(user_id):
        """Admin: Quick view of user's current limit usage (lightweight)"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        today = datetime.utcnow().date()
        command_usage = CommandUsage.query.filter_by(user_id=user.id, command_date=today).first()
        
        # Get login attempts from last hour
        cutoff = datetime.utcnow() - timedelta(hours=1)
        login_attempts = LoginAttempt.query.filter(
            LoginAttempt.identifier == user.email,
            LoginAttempt.attempt_time >= cutoff
        ).count()
        
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            },
            'command_limit': {
                'used_today': command_usage.count if command_usage else 0,
                'limit_per_day': 100,
                'remaining': 100 - (command_usage.count if command_usage else 0),
                'resets_at_midnight': True
            },
            'login_limit': {
                'attempts_last_hour': login_attempts,
                'limit_per_hour': 10,
                'remaining': max(0, 10 - login_attempts)
            }
        })

    @app.route('/api/admin/user-dashboard/<int:user_id>')
    @login_required
    def admin_view_user_dashboard(user_id):
        """Admin: Complete user dashboard (detailed view)"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get devices
        devices = Device.query.filter_by(user_id=user.id).order_by(Device.created_at.desc()).all()
        active_devices = [d for d in devices if d.is_active]
        
        # Get sessions
        active_sessions = UserSession.query.filter(
            UserSession.user_id == user.id,
            UserSession.is_active == True,
            UserSession.expires_at > datetime.utcnow()
        ).count()
        
        # Get command usage for last 7 days
        today = datetime.utcnow().date()
        command_stats = []
        for i in range(7):
            date = today - timedelta(days=i)
            usage = CommandUsage.query.filter_by(user_id=user.id, command_date=date).first()
            command_stats.append({
                'date': date.isoformat(),
                'count': usage.count if usage else 0
            })
        
        # Get login attempts (last 24 hours)
        cutoff = datetime.utcnow() - timedelta(hours=24)
        recent_login_attempts = LoginAttempt.query.filter(
            LoginAttempt.identifier == user.email,
            LoginAttempt.attempt_time >= cutoff
        ).order_by(LoginAttempt.attempt_time.desc()).limit(20).all()
        
        login_attempts_data = [{
            'time': attempt.attempt_time.isoformat(),
            'success': attempt.success,
            'ip': attempt.ip_address
        } for attempt in recent_login_attempts]
        
        # Get recent activity logs
        recent_activity = SystemLog.query.filter_by(user_id=user.id).order_by(SystemLog.created_at.desc()).limit(20).all()
        
        activity_data = [{
            'time': log.created_at.isoformat(),
            'type': log.log_type,
            'message': log.message,
            'ip': log.ip_address
        } for log in recent_activity]
        
        # Get credit transactions (last 20)
        transactions = CreditTransaction.query.filter_by(user_id=user.id).order_by(CreditTransaction.created_at.desc()).limit(20).all()
        
        transactions_data = [{
            'date': t.created_at.isoformat(),
            'amount': t.amount,
            'type': t.transaction_type,
            'description': t.description
        } for t in transactions]
        
        # Calculate days remaining on license
        days_remaining = 0
        if user.license_expiry_date:
            days_remaining = (user.license_expiry_date - datetime.utcnow()).days
            if days_remaining < 0:
                days_remaining = 0
        
        # Get HWID change count
        hwid_changes = user.hwid_change_count or 0
        
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'admission_number': user.admission_number,
                'country': user.country or 'Not set',
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'is_banned': user.is_banned,
                'is_admin': user.is_admin,
                'is_reseller': user.is_reseller
            },
            'license': {
                'type': user.license_type or 'None',
                'status': 'Active' if user.is_license_valid() else 'Expired',
                'expiry_date': user.license_expiry_date.isoformat() if user.license_expiry_date else None,
                'days_remaining': days_remaining,
                'device_limit': user.device_limit if user.device_limit < 999999 else 'Unlimited'
            },
            'credits': {
                'balance': user.credits or 0,
                'total_earned': db.session.query(func.sum(CreditTransaction.amount)).filter(CreditTransaction.user_id == user.id, CreditTransaction.amount > 0).scalar() or 0,
                'total_spent': abs(db.session.query(func.sum(CreditTransaction.amount)).filter(CreditTransaction.user_id == user.id, CreditTransaction.amount < 0).scalar() or 0)
            },
            'devices': {
                'total': len(devices),
                'active': len(active_devices),
                'limit': user.device_limit,
                'list': [{
                    'id': d.id,
                    'name': d.device_name,
                    'hwid': d.hwid_hash[:16] + '...' if d.hwid_hash else 'N/A',
                    'is_active': d.is_active,
                    'last_seen': d.last_seen.isoformat() if d.last_seen else None,
                    'created_at': d.created_at.isoformat() if d.created_at else None
                } for d in devices[:10]]
            },
            'sessions': {
                'active': active_sessions
            },
            'commands': {
                'used_today': command_stats[0]['count'] if command_stats else 0,
                'limit_per_day': 100,
                'remaining_today': 100 - (command_stats[0]['count'] if command_stats else 0),
                'last_7_days': command_stats,
                'hwid_change_count': hwid_changes
            },
            'security': {
                'recent_login_attempts': login_attempts_data,
                'failed_attempts_last_hour': LoginAttempt.query.filter(
                    LoginAttempt.identifier == user.email,
                    LoginAttempt.success == False,
                    LoginAttempt.attempt_time >= (datetime.utcnow() - timedelta(hours=1))
                ).count()
            },
            'activity': {
                'recent': activity_data
            },
            'transactions': transactions_data
        })

    @app.route('/api/admin/user-dashboard', methods=['POST'])
    @login_required
    def admin_view_user_dashboard_by_search():
        """Admin: View user dashboard by username or email (convenience method)"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        
        user = None
        if username:
            user = User.query.filter_by(username=username).first()
        elif email:
            user = User.query.filter_by(email=email).first()
        else:
            return jsonify({'error': 'Please provide username or email'}), 400
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Reuse the dashboard function
        return admin_view_user_dashboard(user.id)



    # ==================== ADMIN RESET ACTION ENDPOINTS ====================

    @app.route('/api/admin/reset-command-limit', methods=['POST'])
    @login_required
    def admin_reset_command_limit():
        """Admin: Reset command usage limit for a specific user"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        user_id = data.get('user_id')
        username = data.get('username')
        email = data.get('email')
        
        user = None
        if user_id:
            user = User.query.get(user_id)
        elif username:
            user = User.query.filter_by(username=username).first()
        elif email:
            user = User.query.filter_by(email=email).first()
        else:
            return jsonify({'error': 'Please provide user_id, username, or email'}), 400
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        today = datetime.utcnow().date()
        usage = CommandUsage.query.filter_by(user_id=user.id, command_date=today).first()
        
        if usage:
            old_count = usage.count
            usage.count = 0
            db.session.commit()
            
            log_system_action(current_user.id, 'reset_command_limit', 
                             f"Reset command limit for user {user.username} from {old_count} to 0")
            
            return jsonify({
                'success': True,
                'message': f'Command limit reset for user {user.username}',
                'previous_count': old_count
            })
        else:
            return jsonify({
                'success': True,
                'message': f'User {user.username} has no command usage today'
            })

    @app.route('/api/admin/reset-command-limit-all', methods=['POST'])
    @login_required
    def admin_reset_command_limit_all():
        """Admin: Reset command limits for ALL users (for maintenance)"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        today = datetime.utcnow().date()
        updated = CommandUsage.query.filter_by(command_date=today).update({'count': 0})
        db.session.commit()
        
        log_system_action(current_user.id, 'reset_all_command_limits', 
                         f"Reset command limits for {updated} users")
        
        return jsonify({
            'success': True,
            'message': f'Command limits reset for {updated} users',
            'users_reset': updated
        })
        
    @app.route('/api/admin/reset-login-attempts', methods=['POST'])
    @login_required
    def admin_reset_login_attempts():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403

        data = request.get_json()
        identifier = data.get('identifier')
        user_id = data.get('user_id')

        if not identifier and not user_id:
            return jsonify({'error': 'Please provide identifier or user_id'}), 400

        user = None
        if user_id:
            user = User.query.get(user_id)
            if not user:
                return jsonify({'error': 'User not found'}), 404
        elif identifier:
            user = User.query.filter_by(email=identifier).first()
            if not user:
                user = User.query.filter_by(username=identifier).first()

        deleted_count = 0
        possible_identifiers = []

        if user:
            possible_identifiers = list(filter(None, [
                user.email,
                user.username,
                str(user.admission_number) if user.admission_number else None,
            ]))

            for ident in possible_identifiers:
                count = LoginAttempt.query.filter(
                    LoginAttempt.identifier == ident,
                    LoginAttempt.attempt_type == 'login'
                ).delete(synchronize_session=False)
                deleted_count += count

            user.suspended_until = None
            user.failed_login_count = 0
            db.session.commit()

        else:
            deleted_count = LoginAttempt.query.filter(
                LoginAttempt.identifier == identifier,
                LoginAttempt.attempt_type == 'login'
            ).delete(synchronize_session=False)
            db.session.commit()
            possible_identifiers = [identifier]

        log_system_action(
            current_user.id,
            'reset_login_attempts',
            f"Reset login attempts for {user.username if user else identifier}, "
            f"deleted {deleted_count} records"
        )

        return jsonify({
            'success': True,
            'message': f'Reset complete. {deleted_count} attempt records deleted. Suspension cleared.',
            'deleted_attempts': deleted_count,
            'identifiers_checked': possible_identifiers,
            'suspension_cleared': bool(user)
        })

        
    @app.route('/api/admin/debug-user/<string:identifier>', methods=['GET'])
    @login_required
    def debug_user(identifier):
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        user = User.query.filter_by(email=identifier).first()
        if not user:
            user = User.query.filter_by(username=identifier).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get login attempts
        attempts = LoginAttempt.query.filter(
            LoginAttempt.identifier == user.email,
            LoginAttempt.attempt_type == 'login'
        ).order_by(LoginAttempt.attempt_time.desc()).limit(10).all()
        
        attempts_data = [{
            'time': a.attempt_time.isoformat(),
            'success': a.success,
            'ip': a.ip_address
        } for a in attempts]
        
        return jsonify({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'suspended_until': user.suspended_until.isoformat() if user.suspended_until else None,
                'failed_login_count': user.failed_login_count
            },
            'recent_attempts': attempts_data,
            'attempts_count': len(attempts_data)
        })

        # ==================== RESELLER DASHBOARD API ENDPOINTS ====================

    @app.route('/api/reseller/dashboard')
    @api_login_required
    def reseller_dashboard_api():
        """Get reseller dashboard data"""
        try:
            user = current_user
            if not user.is_reseller and not user.is_admin:
                return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            
            # Refresh user data from database to get latest counts
            db.session.refresh(user)
            
            # Get clients (users activated by this reseller)
            clients = User.query.filter_by(activated_by=user.id).all()
            total_clients = len(clients)
            
            # Count active vs expired licenses
            active_clients = sum(1 for c in clients if c.is_license_valid() and not c.is_banned)
            expired_clients = sum(1 for c in clients if not c.is_license_valid() and not c.is_banned)
            
            # Get current month activations
            current_month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            this_month_clients = User.query.filter(
                User.activated_by == user.id,
                User.created_at >= current_month_start
            ).count()
            
            # Calculate earnings
            total_earnings = user.total_commission or 0
            this_month_earnings = 0
            
            # Get pending approval requests (clients with pending status)
            pending_requests = User.query.filter_by(activated_by=user.id, license_status='pending').count()
            
            return jsonify({
                'success': True,
                'username': user.username,
                'email': user.email,
                'country': user.country or 'Not specified',
                'admission_number': user.admission_number,
                'reseller_id': f'RD-{user.id}',
                'commission_rate': user.commission_rate or 15,
                'total_earnings': total_earnings,
                'credits': user.credits or 0,
                'wallet_balance': user.credits or 0,  # ADD THIS LINE - Reseller's wallet balance
                'this_month_earnings': this_month_earnings,
                'total_clients': total_clients,
                'active_clients': active_clients,
                'expired_clients': expired_clients,
                'this_month_clients': this_month_clients,
                'pending_requests': pending_requests,
                'activations_used': user.activations_used or 0,
                'activation_limit': user.activation_limit or 10
            })
        except Exception as e:
            print(f"Error in reseller_dashboard_api: {e}")
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500
            
    
    @app.route('/api/reseller/clients')
    @api_login_required
    def reseller_clients_api():
        """Get reseller's clients"""
        try:
            user = current_user
            if not user.is_reseller and not user.is_admin:
                return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            
            filter_type = request.args.get('filter', 'all')
            search = request.args.get('search', '').lower()
            page = int(request.args.get('page', 1))
            limit = int(request.args.get('limit', 10))
            offset = (page - 1) * limit
            
            query = User.query.filter_by(activated_by=user.id)
            
            if filter_type == 'active':
                query = query.filter(User.license_expiry_date > datetime.utcnow(), User.is_banned == False)
            elif filter_type == 'expired':
                query = query.filter(User.license_expiry_date <= datetime.utcnow(), User.license_expiry_date.isnot(None))
            elif filter_type == 'pending':
                query = query.filter_by(license_status='pending')
            
            if search:
                query = query.filter(
                    or_(
                        User.username.ilike(f'%{search}%'),
                        User.email.ilike(f'%{search}%'),
                        User.admission_number.cast().ilike(f'%{search}%')
                    )
                )
            
            total = query.count()
            clients = query.offset(offset).limit(limit).all()
            
            clients_data = [{
                'id': c.id,
                'username': c.username,
                'email': c.email,
                'admission_number': c.admission_number,
                'country': c.country,
                'license_type': c.license_type or 'None',
                'license_expiry': c.license_expiry_date.isoformat() if c.license_expiry_date else None,
                'is_active': c.is_license_valid(),
                'is_banned': c.is_banned,
                'created_at': c.created_at.isoformat() if c.created_at else None
            } for c in clients]
            
            return jsonify({
                'success': True,
                'clients': clients_data,
                'total': total,
                'page': page,
                'limit': limit
            })
        except Exception as e:
            print(f"Error in reseller_clients_api: {e}")
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500
    
    
    @app.route('/api/reseller/earnings')
    @api_login_required
    def reseller_earnings_api():
        """Get reseller earnings data"""
        try:
            user = current_user
            if not user.is_reseller and not user.is_admin:
                return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            
            # Get all credit transactions from this reseller's clients
            transactions = CreditTransaction.query.filter_by(created_by=user.id).order_by(CreditTransaction.created_at.desc()).limit(50).all()
            
            transactions_data = []
            for t in transactions:
                client = User.query.get(t.user_id)
                transactions_data.append({
                    'date': t.created_at.isoformat() if t.created_at else None,
                    'client_name': client.username if client else 'Unknown',
                    'license_type': t.description,
                    'amount': abs(t.amount),
                    'commission': abs(t.amount) * (user.commission_rate or 15) // 100,
                    'status': 'paid'
                })
            
            total_earnings = sum(t['commission'] for t in transactions_data)
            this_month_earnings = 0
            pending_earnings = 0
            
            return jsonify({
                'success': True,
                'transactions': transactions_data,
                'total_earnings': total_earnings,
                'this_month': this_month_earnings,
                'pending': pending_earnings
            })
        except Exception as e:
            print(f"Error in reseller_earnings_api: {e}")
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/reseller/history')
    @api_login_required
    def reseller_history_api():
        """Get reseller activation history"""
        try:
            user = current_user
            if not user.is_reseller and not user.is_admin:
                return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            
            # Get all clients activated by this reseller
            clients = User.query.filter_by(activated_by=user.id).order_by(User.created_at.desc()).limit(50).all()
            
            history_data = [{
                'id': c.id,
                'client_name': c.username,
                'client_email': c.email,
                'license_type': c.license_type,
                'amount': 0,
                'commission': 0,
                'status': 'Active' if c.is_license_valid() else 'Expired',
                'date': c.created_at.isoformat() if c.created_at else None
            } for c in clients]
            
            return jsonify({
                'success': True,
                'history': history_data,
                'total': len(history_data)
            })
        except Exception as e:
            print(f"Error in reseller_history_api: {e}")
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500


            # ==================== DIRECT ACTIVATION (RESELLERS) ====================
    @app.route('/api/reseller/activate', methods=['POST'])
    @api_login_required
    def reseller_activate_license():
        """Activate license - supports both: create new user OR activate existing user"""
        try:
            user = current_user
            if not user.is_reseller and not user.is_admin:
                return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            
            # Check activation limit for resellers
            if user.is_reseller:
                used = user.activations_used or 0
                limit = user.activation_limit or 10
                if used >= limit:
                    return jsonify({
                        'success': False, 
                        'error': f'Activation limit reached ({used}/{limit})'
                    }), 403
            
            data = request.get_json()
            email = data.get('email', '').strip().lower()
            license_type = data.get('license_type', '12hr')
            
            # Check which mode we're in based on provided fields
            full_name = data.get('full_name', '').strip()
            country = data.get('country', '')
            
            # Reseller durations and device limits
            durations = {
                '12hr': 0.5,  # 12 hours = 0.5 days
                '24hr': 1,
                '3_months': 90,
                '6_months': 180,
                '1_year': 365
            }
            device_limits = {
                '12hr': 1,
                '24hr': 1,
                '3_months': 10,
                '6_months': 20,
                '1_year': 45
            }
            
            # Handle 12hr and 24hr as hours, others as days
            if license_type == '12hr':
                expiry = datetime.utcnow() + timedelta(hours=12)
                days = 0.5
            elif license_type == '24hr':
                expiry = datetime.utcnow() + timedelta(hours=24)
                days = 1
            else:
                days = durations.get(license_type, 90)
                expiry = datetime.utcnow() + timedelta(days=days)
            
            device_limit = device_limits.get(license_type, 1)
            
            import random
            import string
            
            # Check if user already exists
            existing_user = User.query.filter_by(email=email).first()
            
            if existing_user:
                # ========== OPTION 1: NORMAL ACTIVATION (Email only) ==========
                # Check if this user is already activated by another reseller
                if existing_user.activated_by and existing_user.activated_by != user.id and not user.is_admin:
                    return jsonify({
                        'success': False, 
                        'error': f'User {email} is already managed by another reseller',
                        'code': 'ALREADY_ASSIGNED'
                    }), 403
                
                # Update existing user's license
                existing_user.license_type = license_type
                existing_user.license_expiry_date = expiry
                existing_user.device_limit = device_limit
                existing_user.license_status = 'active'
                
                # Set activated_by if not already set
                if not existing_user.activated_by:
                    existing_user.activated_by = user.id
                
                db.session.commit()
                
                # Increment activation count for reseller
                if user.is_reseller:
                    user.activations_used = (user.activations_used or 0) + 1
                    db.session.commit()
                
                log_system_action(user.id, 'reseller_activate_existing', 
                                f'Activated {license_type} for existing user {email}')
                
                # Send email notification to user about license activation
                send_license_activation_email(email, existing_user.username, license_type, days)
                
                return jsonify({
                    'success': True,
                    'message': f'License activated for existing user {email}',
                    'activation_type': 'existing_user',
                    'client': {
                        'username': existing_user.username,
                        'email': existing_user.email,
                        'admission_number': existing_user.admission_number,
                        'license_type': license_type,
                        'days': days,
                        'device_limit': device_limit,
                        'already_registered': True
                    }
                })
            
            else:
                # ========== OPTION 2: DIRECT REGISTRATION (Full name, email, country) ==========
                if not full_name:
                    return jsonify({
                        'success': False, 
                        'error': 'Full name required for direct registration',
                        'required_fields': ['full_name', 'email', 'country']
                    }), 400
                
                if not country:
                    return jsonify({
                        'success': False, 
                        'error': 'Country required for direct registration',
                        'required_fields': ['full_name', 'email', 'country']
                    }), 400
                
                # Generate username from full name
                username = full_name.lower().replace(' ', '.')
                base = username
                counter = 1
                while User.query.filter_by(username=username).first():
                    username = f"{base}{counter}"
                    counter += 1
                
                admission_number = get_next_admission_number()
                
                # Generate strong password
                temp_password = ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%", k=12))
                
                # Create new user - NO license_valid field!
                new_user = User(
                    username=username,
                    email=email,
                    country=country,
                    admission_number=admission_number,
                    credits=0,
                    device_limit=device_limit,
                    license_type=license_type,
                    license_expiry_date=expiry,
                    license_status='active',
                    activated_by=current_user.id
                )
                new_user.set_password(temp_password)
                db.session.add(new_user)
                
                # Increment activation count
                if current_user.is_reseller:
                    current_user.activations_used = (current_user.activations_used or 0) + 1
                
                db.session.commit()
                
                # Send email with credentials and license info
                send_welcome_email_with_credentials(email, username, temp_password, license_type, days, admission_number)
                
                log_system_action(current_user.id, 'reseller_activate_new', 
                                f'Created and activated {license_type} for new user {email}')
                
                return jsonify({
                    'success': True,
                    'message': f'New user created and license activated for {email}. Credentials sent to email.',
                    'activation_type': 'new_user',
                    'temp_password': temp_password,
                    'client': {
                        'username': username,
                        'email': email,
                        'admission_number': admission_number,
                        'country': country,
                        'license_type': license_type,
                        'days': days,
                        'device_limit': device_limit,
                        'already_registered': False
                    }
                })
                
        except Exception as e:
            db.session.rollback()
            print(f"Error in reseller_activate_license: {e}")
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500

    # ==================== RESELLER ASSIGN CREDITS TO CLIENT ====================
    @app.route('/api/reseller/assign-credits', methods=['POST'])
    @api_login_required
    def reseller_assign_credits():
        """Reseller can assign credits to their clients from their wallet"""
        try:
            user = current_user
            if not user.is_reseller and not user.is_admin:
                return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            
            data = request.get_json()
            client_email = data.get('email', '').strip().lower()
            amount = data.get('amount', 0)
            reason = data.get('reason', 'Credits assigned by reseller')
            
            # Validate amount
            if not amount or amount <= 0:
                return jsonify({'success': False, 'error': 'Amount must be greater than 0'}), 400
            
            # Check if reseller has enough credits
            if (user.credits or 0) < amount:
                return jsonify({
                    'success': False, 
                    'error': f'Insufficient credits. You have {user.credits or 0} credits, need {amount}'
                }), 400
            
            # Find the client (must be activated by this reseller)
            client = User.query.filter_by(email=client_email).first()
            if not client:
                return jsonify({'success': False, 'error': 'Client not found'}), 404
            
            # Check if client belongs to this reseller
            if client.activated_by != user.id:
                return jsonify({'success': False, 'error': 'This client is not associated with you'}), 403
            
            # Deduct credits from reseller
            user.credits = (user.credits or 0) - amount
            
            # Add credits to client
            client.credits = (client.credits or 0) + amount
            
            # Create transaction records
            # Reseller deduction
            reseller_transaction = CreditTransaction(
                user_id=user.id,
                amount=-amount,
                transaction_type='reseller_gift',
                description=f'Assigned {amount} credits to client {client.email}',
                created_by=user.id
            )
            db.session.add(reseller_transaction)
            
            # Client addition
            client_transaction = CreditTransaction(
                user_id=client.id,
                amount=amount,
                transaction_type='reseller_gift',
                description=f'Credits assigned by reseller {user.username}',
                created_by=user.id
            )
            db.session.add(client_transaction)
            
            db.session.commit()
            
            log_system_action(user.id, 'reseller_assign_credits', 
                            f'Assigned {amount} credits to client {client.username} ({client.email})')
            
            return jsonify({
                'success': True,
                'message': f'Successfully assigned {amount} credits to {client.username}',
                'reseller_credits_remaining': user.credits,
                'client_credits_new': client.credits,
                'client': {
                    'username': client.username,
                    'email': client.email,
                    'credits': client.credits
                }
            }), 200
            
        except Exception as e:
            db.session.rollback()
            print(f"Error in reseller_assign_credits: {e}")
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500


    # ==================== RESELLER GET CLIENT CREDITS BALANCE ====================
    @app.route('/api/reseller/client-credits/<string:client_email>')
    @api_login_required
    def reseller_get_client_credits(client_email):
        """Get client's current credits balance"""
        try:
            user = current_user
            if not user.is_reseller and not user.is_admin:
                return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            
            # Find the client
            client = User.query.filter_by(email=client_email).first()
            if not client:
                return jsonify({'success': False, 'error': 'Client not found'}), 404
            
            # Check if client belongs to this reseller
            if client.activated_by != user.id:
                return jsonify({'success': False, 'error': 'This client is not associated with you'}), 403
            
            return jsonify({
                'success': True,
                'client': {
                    'username': client.username,
                    'email': client.email,
                    'credits': client.credits or 0
                }
            }), 200
            
        except Exception as e:
            print(f"Error in reseller_get_client_credits: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500



            
   # ==================== ADMIN RESELLER MANAGEMENT ENDPOINTS ====================
    
    @app.route('/api/admin/remove-reseller/<int:user_id>', methods=['DELETE', 'POST'])
    @login_required
    def admin_remove_reseller(user_id):
        """Remove reseller status from a user"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Remove reseller status
        user.is_reseller = False
        user.commission_rate = 0
        
        db.session.commit()
        
        log_system_action(current_user.id, 'remove_reseller', f'Removed reseller status from {user.username}')
        
        return jsonify({'success': True, 'message': f'Reseller status removed from {user.username}'})
    
    @app.route('/api/admin/update-reseller-commission/<int:user_id>', methods=['POST'])
    @login_required
    def admin_update_reseller_commission(user_id):
        """Update reseller commission rate"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        commission_rate = data.get('commission_rate', 15)
        
        if commission_rate < 0 or commission_rate > 100:
            return jsonify({'error': 'Commission rate must be between 0 and 100'}), 400
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if not user.is_reseller:
            return jsonify({'error': 'User is not a reseller'}), 400
        
        user.commission_rate = commission_rate
        db.session.commit()
        
        log_system_action(current_user.id, 'update_commission', f'Updated {user.username}\'s commission to {commission_rate}%')
        
        return jsonify({'success': True, 'message': f'Commission rate updated to {commission_rate}%'})
    
    @app.route('/api/admin/get-resellers')
    @login_required
    def admin_get_resellers():
        """Get all resellers"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        resellers = User.query.filter_by(is_reseller=True).all()
        
        resellers_data = [{
            'id': r.id,
            'username': r.username,
            'email': r.email,
            'admission_number': r.admission_number,
            'commission_rate': r.commission_rate or 15,
            'credits': r.credits or 0,
            'total_sales': r.total_sales or 0,
            'total_commission': r.total_commission or 0,
            'client_count': User.query.filter_by(activated_by=r.id).count(),
            'created_at': r.created_at.isoformat() if r.created_at else None
        } for r in resellers]
        
        return jsonify({
            'success': True,
            'resellers': resellers_data,
            'total': len(resellers_data)
        })
    
    
    


            # ==================== STATIC PAGE ROUTES ====================
    
    @app.route('/supported-models')
    def supported_models():
        """Supported models page"""
        return render_template('supported_models.html')
    
    @app.route('/pricing')
    def pricing():
        """Pricing page"""
        return render_template('pricing.html')
    
    @app.route('/resellers')
    def resellers():
        """Reseller information page"""
        return render_template('resellers.html')
    
    @app.route('/contact')
    def contact():
        """Contact page"""
        return render_template('contact.html')
    
    @app.route('/faq')
    def faq():
        """FAQ page"""
        return render_template('faq.html')
    
    @app.route('/features')
    def features():
        """Features page"""
        return render_template('features.html')
    
    @app.route('/documentation')
    def documentation():
        """Documentation page"""
        return render_template('documentation.html')
    
    @app.route('/download')
    def download():
        """Download page"""
        return render_template('download.html')
    
    @app.route('/changelog')
    def changelog():
        """Changelog page"""
        return render_template('changelog.html')
    
    @app.route('/terms')
    def terms():
        """Terms of service page"""
        return render_template('terms.html')
    
    @app.route('/privacy')
    def privacy():
        """Privacy policy page"""
        return render_template('privacy.html')
    
    @app.route('/license')
    def license():
        """License agreement page"""
        return render_template('license.html')

                # ==================== COMMAND FETCH ENDPOINT ====================###############################
    @app.route('/api/get-command', methods=['POST'])
    @limiter.limit("100 per day") 
    @api_login_required
    def get_command():
        """
        Fetch command definition for desktop client
        Expects: {"tab": "mediatek", "mode": "mdm", "action": "read_info", "device_info": {}, "security_info": {}}
        """
        try:
            # ========== CHECK MAINTENANCE MODE ==========
            if is_maintenance_mode():
                return jsonify({
                    'error': 'Server under maintenance. Please check back later. Thank you for your patience.',
                    'code': 'MAINTENANCE_MODE',
                    'maintenance': True
                }), 503
            
            data = request.get_json()
            tab = data.get('tab', '').lower()        # mediatek, unisoc, xiaomi, hmd, hxd
            mode = data.get('mode', '').lower()      # mdm, adb, fastboot, etc.
            action = data.get('action', '').lower()  # read_info, factory_reset, etc.
            device_info = data.get('device_info', {})
            client_security_info = data.get('security_info', {})  # Get security info from client
            
            # DEBUG: Print what we're looking for
            print(f"🔍 [DEBUG] Looking for: tab={tab}, mode={mode}, action={action}")
            
            user = current_user
            
            # 1. VALIDATION
            if user.is_banned:
                ban_msg = "Account banned"
                if user.suspended_until and user.suspended_until > datetime.utcnow():
                    remaining = (user.suspended_until - datetime.utcnow())
                    hours = int(remaining.total_seconds() // 3600)
                    minutes = int((remaining.total_seconds() % 3600) // 60)
                    ban_msg += f" - Remaining: {hours}h {minutes}m"
                
                return jsonify({
                    'error': ban_msg,
                    'code': 'BANNED',
                    'security_violation': True,
                    'block_reason': ban_msg,
                    'banned': True,
                    'ban_until': user.suspended_until.isoformat() if user.suspended_until else None
                }), 403
            
            if not user.is_license_valid():
                return jsonify({
                    'error': 'License expired/not activated',
                    'code': 'LICENSE_EXPIRED'
                }), 403
            
            # ========== SECURITY CHECK - SERVER CONTROLS THIS ==========
            security_allowed, block_reason, tamper_count, remaining_attempts = check_client_security(
                user.id, client_security_info
            )
            
            if not security_allowed:
                # Block the command - server controls this
                return jsonify({
                    'error': f'⚠️ COMMAND BLOCKED: {block_reason}',
                    'code': 'SECURITY_BLOCK',
                    'security_violation': True,
                    'block_reason': block_reason,
                    'tamper_count': tamper_count,
                    'remaining_attempts': remaining_attempts,
                    'max_attempts': 3,
                    'warning': remaining_attempts <= 1,
                    'requires_admin_intervention': tamper_count >= 3,
                    'commands_used_today': 0,
                    'commands_limit_today': 100,
                    'commands_remaining_today': 100
                }), 403
            
            # ========== COMMAND LIMIT CHECK (100 per day) ==========
            allowed, count, remaining = check_command_limit(user.id)
            
            if not allowed:
                return jsonify({
                    'error': f'Command limit reached. You have used {count}/100 commands today.',
                    'code': 'COMMAND_LIMIT_REACHED',
                    'commands_used': count,
                    'commands_limit': 100,
                    'commands_remaining': 0,
                    'resets_at_midnight': True
                }), 429
            
            # 2. MAP TAB to folder name
            tab_folders = {
                'mediatek': 'mediatek_module',
                'unisoc': 'unisoc_module',
                'xiaomi': 'xiaomi_module',
                'samsung': 'samsung_module',
                'oplus': 'oplus_module',
                'hxd': 'hxd_module',
            }
            
            folder = tab_folders.get(tab)
            if not folder:
                return jsonify({'error': f'Invalid tab: {tab}'}), 404
            
            # 3. MAP MODE to JSON file
            filename = f"{mode}_commands.json"
            
            # 4. LOAD COMMANDS FROM SERVER
            commands_dir = os.path.join(BASE_DIR, 'commands')
            filepath = os.path.join(commands_dir, folder, filename)
            
            # Check if file exists with fallback paths
            if not os.path.exists(filepath):
                alt_paths = [
                    os.path.join(os.getcwd(), 'commands'),
                    os.path.join(os.path.dirname(os.path.dirname(BASE_DIR)), 'commands'),
                ]
                for alt in alt_paths:
                    alt_filepath = os.path.join(alt, folder, filename)
                    if os.path.exists(alt_filepath):
                        filepath = alt_filepath
                        break
                
                if not os.path.exists(filepath):
                    return jsonify({
                        'error': f'Commands not found for {tab}/{mode}',
                        'debug': {
                            'filepath': filepath,
                            'requested_tab': tab,
                            'requested_mode': mode,
                            'requested_action': action
                        }
                    }), 404
            
            with open(filepath, 'r') as f:
                commands_data = json.load(f)
            
            # 5. GET SPECIFIC ACTION
            function_data = commands_data.get('functions', {}).get(action)
            
            if not function_data:
                # Try case-insensitive search
                for key, value in commands_data.get('functions', {}).items():
                    if key.lower() == action:
                        function_data = value
                        break
                
                if not function_data:
                    available_actions = list(commands_data.get('functions', {}).keys())
                    return jsonify({
                        'error': f'Action "{action}" not found. Available: {available_actions}'
                    }), 404
            
            # 6. CHECK PERMISSIONS
            if function_data.get('requires_admin', False) and not user.is_admin:
                return jsonify({'error': 'Admin access required'}), 403
            
            # ========== CUSTOM CREDIT LOGIC FOR XIAOMI TAB ==========
            # Get base cost from JSON
            cost = function_data.get('cost', 0)
            original_cost = cost  # Store for logging
            
            # Apply Xiaomi special pricing
            if tab == 'xiaomi':
                if action == 'read_info':
                    cost = 0  # Free
                    print(f"💰 [XIAOMI] read_info is FREE (original cost: {original_cost})")
                else:
                    cost = 5  # 5 credits for any other Xiaomi operation
                    print(f"💰 [XIAOMI] Setting cost to 5 credits for {action} (original cost: {original_cost})")
            
            # 7. CHECK CREDITS
            if cost > 0 and (user.credits or 0) < cost:
                return jsonify({
                    'error': f'Insufficient credits. Need {cost} credits', 
                    'code': 'INSUFFICIENT_CREDITS',
                    'credits_available': user.credits or 0,
                    'credits_needed': cost
                }), 403
            
            # 8. DEDUCT CREDITS if cost > 0
            if cost > 0:
                user.credits = (user.credits or 0) - cost
                transaction = CreditTransaction(
                    user_id=user.id,
                    amount=-cost,
                    transaction_type='command_usage',
                    description=f'Executed {tab}.{mode}.{action} (Cost: {cost} credits)'
                )
                db.session.add(transaction)
                db.session.commit()
                print(f"💰 Deducted {cost} credits from user {user.username} (Remaining: {user.credits})")
            
            # ========== INCREMENT COMMAND COUNTER ==========
            new_command_count = increment_command_count(user.id)
            print(f"📊 Command count for today: {new_command_count}/100")
            
            # 9. LOG REQUEST
            log_system_action(user.id, 'command_request', 
                             f"Requested {tab}.{mode}.{action} on {device_info.get('model', 'unknown')} (Cost: {cost} credits) (Command {new_command_count}/100 today)")
            
            # 10. BUILD RESPONSE
            response = {
                'success': True,
                'tab': tab,
                'mode': mode,
                'action': action,
                'type': function_data.get('type', 'adb_commands'),
                'requires_device': function_data.get('requires_device', False),
                'device_type': function_data.get('device_type', 'adb'),
                'progress_steps': function_data.get('progress_steps', []),
                'commands': function_data.get('commands', []),
                'filter_keywords': function_data.get('filter_keywords', {}),
                'unique_filters': function_data.get('unique_filters', {}),
                'success_message': function_data.get('success_message', '✅ Operation completed'),
                'error_message': function_data.get('error_message', '❌ Operation failed'),
                'timeout': function_data.get('timeout', 60),
                'chunk_size': function_data.get('chunk_size', 4194304),
                'backup_enabled': function_data.get('backup_enabled', False),
                'cost': cost,
                'original_cost': original_cost,
                'credits_remaining': user.credits or 0,
                'commands_used_today': new_command_count,
                'commands_limit_today': 100,
                'commands_remaining_today': 100 - new_command_count,
                'config': function_data.get('config', {}),
                
                # For meta_action (factory_reset, frp)
                'action_command': function_data.get('action_command', ''),
                # For meta_command (read_info)
                'command': function_data.get('command', ''),
                # For meta_boot (handshake, detection, etc.)
                'handshake': function_data.get('handshake', {}),
                'preloader_detection': function_data.get('preloader_detection', {}),
                'boot_methods': function_data.get('boot_methods', []),
                'meta_detection': function_data.get('meta_detection', {}),
                'final_progress': function_data.get('final_progress', 100),
                # For nvram operations
                'partitions': function_data.get('partitions', []),
                'operation': function_data.get('operation', ''),
                'progress_per_partition': function_data.get('progress_per_partition', 80),
                'output_format': function_data.get('output_format', ''),
                'input_format': function_data.get('input_format', ''),
                # For imei operations
                'parse_response': function_data.get('parse_response', {}),
                'default_info': function_data.get('default_info', []),
                'requires_connection': function_data.get('requires_connection', False),
                'requires_auth': function_data.get('requires_auth', False),
                'requires_imei': function_data.get('requires_imei', False),
                # For stop operation
                'disconnect_command': function_data.get('disconnect_command', ''),
                'disconnect_delay': function_data.get('disconnect_delay', 0.5),
                'reset_connection': function_data.get('reset_connection', False),
                
                # ========== APK DOWNLOAD INFORMATION ==========
                'requires_apk': function_data.get('requires_apk', False),
                'apk_name': function_data.get('apk_name', ''),
                'apk_download_url': function_data.get('apk_download_url', ''),
                'apk_package': function_data.get('apk_package', ''),
                
                # ========== PHASES (for progress display) ==========
                'phases': function_data.get('phases', []),
                
                # ========== FOR Dolphin_app_method_v1 (Block method) ==========
                'block_apps': function_data.get('block_apps', []),
                'block_commands_per_app': function_data.get('block_commands_per_app', []),
                
                # ========== FOR Dolphin_No_Dns_Method_v01 (Target apps - CRITICAL!) ==========
                'target_apps': function_data.get('target_apps', []),
                'commands_per_app': function_data.get('commands_per_app', []),
                
                # ========== FOR Dolphin_app_method_v2 (Uninstall method) ==========
                'uninstall_apps': function_data.get('uninstall_apps', []),
                'uninstall_commands': function_data.get('uninstall_commands', []),
                
                # ========== FOR Dolphin_No_Dns_Method_v02 (Pre-uninstall + Uninstall) ==========
                'pre_uninstall_commands': function_data.get('pre_uninstall_commands', []),
                
                # ========== FOR Disable_System_Updates ==========
                'disable_commands': function_data.get('disable_commands', []),
                
                # ========== GLOBAL SETTINGS / COMMANDS ==========
                'global_settings': function_data.get('global_settings', []),
                'global_commands': function_data.get('global_commands', []),
                'global_cleanup': function_data.get('global_cleanup', []),
                
                # ========== DEVICE OWNER & PERMISSIONS ==========
                'set_device_owner': function_data.get('set_device_owner', {}),
                'grant_permissions': function_data.get('grant_permissions', []),
                'launch_methods': function_data.get('launch_methods', []),
                
                # ========== REBOOT FLAG ==========
                'reboot': function_data.get('reboot', False)
            }
            print(f"✅ Command fetched: {tab}/{mode}/{action} (Cost: {cost} credits) (Command {new_command_count}/100 today)")
            
            # 🔒 ENCRYPT RESPONSE
            import base64
            
            session_key = ''
            
            # Try all sources for session key
            auth = request.headers.get('Authorization', '')
            if auth.startswith('Bearer '):
                session_key = auth.split(' ')[1]
            
            if not session_key:
                session_key = data.get('session_token', '')
            
            if not session_key:
                session_key = user.current_session_key or ''
            
            if not session_key:
                session_key = flask_session.get('module_key', '')
            
            if session_key:
                key = hashlib.sha256(session_key.encode()).digest()
                json_str = json.dumps(response, ensure_ascii=False)
                json_bytes = json_str.encode('utf-8')
                encrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(json_bytes)])
                return jsonify({'encrypted': True, 'data': base64.b64encode(encrypted).decode('utf-8')}), 200
            else:
                return jsonify({'error': 'Encryption required. Please re-login.', 'code': 'NO_SESSION_KEY'}), 403
            
        except Exception as e:
            print(f"Error in get_command: {e}")
            traceback.print_exc()
            return jsonify({'error': f'Internal server error: {str(e)}'}), 500
            

                # ==================== ADMIN SAMSUNG FRP ENDPOINTS ====================
    
    @app.route('/api/admin/samsung/orders', methods=['GET'])
    @login_required
    def admin_samsung_orders():
        """Admin: Get all Samsung FRP orders"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        try:
            from sqlalchemy import func
            from database import SamsungOrder
            
            status_filter = request.args.get('status', 'pending')
            page = int(request.args.get('page', 1))
            limit = int(request.args.get('limit', 20))
            offset = (page - 1) * limit
            
            query = SamsungOrder.query
            if status_filter != 'all':
                query = query.filter_by(status=status_filter)
            
            total = query.count()
            orders = query.order_by(SamsungOrder.created_at.desc()).offset(offset).limit(limit).all()
            
            orders_data = [order.to_dict() for order in orders]
            
            pending_count = SamsungOrder.query.filter_by(status='pending').count()
            processing_count = SamsungOrder.query.filter_by(status='processing').count()
            completed_count = SamsungOrder.query.filter_by(status='completed').count()
            failed_count = SamsungOrder.query.filter_by(status='failed').count()
            
            # Use the global db object (already imported at top of file)
            total_credits_earned = db.session.query(func.sum(SamsungOrder.credits_cost)).filter(SamsungOrder.status == 'completed').scalar() or 0
            
            return jsonify({
                'success': True,
                'orders': orders_data,
                'total': total,
                'page': page,
                'limit': limit,
                'stats': {
                    'pending': pending_count,
                    'processing': processing_count,
                    'completed': completed_count,
                    'failed': failed_count,
                    'total_credits_earned': total_credits_earned
                }
            }), 200
            
        except Exception as e:
            print(f"Error in admin_samsung_orders: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': str(e), 'success': False}), 500
    
    
    @app.route('/api/admin/samsung/order/<int:order_id>/process', methods=['POST'])
    @login_required
    def admin_process_samsung_order(order_id):
        """Admin: Process a Samsung FRP order"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        try:
            data = request.get_json()
            status = data.get('status', 'completed')
            result_code = data.get('result_code', 'SUCCESS')
            result_message = data.get('result_message', '')
            admin_notes = data.get('admin_notes', '')
            
            from database import SamsungOrder
            order = SamsungOrder.query.get(order_id)
            if not order:
                return jsonify({'error': 'Order not found'}), 404
            
            # Update order
            order.status = status
            order.processed_by = current_user.id
            order.processed_at = datetime.utcnow()
            order.result_code = result_code
            order.result_message = result_message
            order.admin_notes = admin_notes
            
            db.session.commit()
            
            log_system_action(current_user.id, 'process_samsung_order', 
                             f'Processed order {order.order_id} - Status: {status}')
            
            if status == 'failed':
                print(f"⚠️ Order {order.order_id} failed. Consider refunding {order.credits_cost} credits to user {order.user_id}")
            
            return jsonify({
                'success': True,
                'message': f'Order {order.order_id} marked as {status}',
                'order': order.to_dict()
            }), 200
            
        except Exception as e:
            db.session.rollback()
            print(f"Error in admin_process_samsung_order: {e}")
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/admin/samsung/order/<int:order_id>/refund', methods=['POST'])
    @login_required
    def admin_refund_samsung_order(order_id):
        """Admin: Refund credits for failed order"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        try:
            from database import SamsungOrder, CreditTransaction, User
            order = SamsungOrder.query.get(order_id)
            if not order:
                return jsonify({'error': 'Order not found'}), 404
            
            if order.status != 'failed':
                return jsonify({'error': 'Can only refund failed orders'}), 400
            
            user = User.query.get(order.user_id)
            if user:
                user.credits = (user.credits or 0) + order.credits_cost
                
                transaction = CreditTransaction(
                    user_id=user.id,
                    amount=order.credits_cost,
                    transaction_type='refund',
                    description=f'Refund for failed Samsung FRP order {order.order_id}'
                )
                db.session.add(transaction)
                
                order.admin_notes = (order.admin_notes or '') + f'\nRefunded {order.credits_cost} credits by {current_user.username}'
                db.session.commit()
                
                log_system_action(current_user.id, 'refund_samsung_order', 
                                 f'Refunded {order.credits_cost} credits for order {order.order_id}')
                
                return jsonify({
                    'success': True,
                    'message': f'Refunded {order.credits_cost} credits to user',
                    'credits_refunded': order.credits_cost
                }), 200
            
            return jsonify({'error': 'User not found'}), 404
            
        except Exception as e:
            db.session.rollback()
            print(f"Error in admin_refund_samsung_order: {e}")
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500
    
    
    # ========== DEBUG ENDPOINT ==========
    @app.route('/api/admin/samsung/debug', methods=['GET'])
    @login_required
    def admin_samsung_debug():
        """Debug endpoint to check Samsung orders"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        try:
            from database import SamsungOrder
            from sqlalchemy import inspect
            
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
            count = SamsungOrder.query.count()
            first_order = SamsungOrder.query.first()
            first_order_data = first_order.to_dict() if first_order else None
            
            return jsonify({
                'success': True,
                'tables': tables,
                'samsung_orders_table_exists': 'samsung_orders' in tables,
                'order_count': count,
                'first_order': first_order_data
            })
        except Exception as e:
            import traceback
            return jsonify({
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }), 500
            
    # ==================== SAMSUNG FRP USER API ENDPOINTS ====================
    
    @app.route('/api/samsung/frp/order', methods=['POST'])
    @api_login_required
    def samsung_frp_create_order():
        """Create Samsung FRP order"""
        try:
            # Check maintenance mode
            if is_maintenance_mode():
                return jsonify({
                    'success': False,
                    'error': 'Server under maintenance',
                    'code': 'MAINTENANCE_MODE'
                }), 503
            
            user = current_user
            
            # Check if user is banned
            if user.is_banned:
                return jsonify({
                    'success': False,
                    'error': 'Account is banned',
                    'code': 'ACCOUNT_BANNED'
                }), 403
            
            # Check license validity
            if not user.is_license_valid():
                return jsonify({
                    'success': False,
                    'error': 'License has expired',
                    'code': 'LICENSE_EXPIRED'
                }), 403
            
            # Get request data
            data = request.get_json()
            if not data:
                return jsonify({'success': False, 'error': 'No JSON data'}), 400
            
            imei = data.get('imei', '').strip()
            android_version = str(data.get('android_version', '')).strip()
            
            # Validate IMEI
            if not imei:
                return jsonify({'success': False, 'error': 'IMEI/Serial required'}), 400
            
            # Validate Android version
            if android_version not in SAMSUNG_FRP_PRICES:
                return jsonify({
                    'success': False,
                    'error': f'Invalid Android version. Supported: 13, 14, 15, 16'
                }), 400
            
            # Get price
            credits_cost = SAMSUNG_FRP_PRICES[android_version]
            
            # Check user credits
            user_credits = user.credits or 0
            if user_credits < credits_cost:
                return jsonify({
                    'success': False,
                    'error': f'Insufficient credits. Need {credits_cost} credits, you have {user_credits}',
                    'code': 'INSUFFICIENT_CREDITS',
                    'credits_needed': credits_cost,
                    'credits_available': user_credits
                }), 403
            
            # Check server status
            server_online = check_samsung_frp_server()
            
            if not server_online:
                return jsonify({
                    'success': False,
                    'error': 'Samsung FRP service is currently offline. Please try again later.',
                    'code': 'SERVER_OFFLINE',
                    'server_status': 'offline'
                }), 503
            
            # Create order
            order_id = generate_order_id()
            
            order_data = {
                'imei': imei,
                'android_version': android_version,
                'credits_cost': credits_cost,
                'user_agent': request.headers.get('User-Agent'),
                'ip_address': get_real_ip()
            }
            
            from database import SamsungOrder
            order = SamsungOrder(
                order_id=order_id,
                user_id=user.id,
                imei=imei,
                android_version=android_version,
                credits_cost=credits_cost,
                status='pending',
                order_data=json.dumps(order_data)
            )
            db.session.add(order)
            
            # Deduct credits
            user.credits = user_credits - credits_cost
            
            # Create transaction record
            from database import CreditTransaction
            transaction = CreditTransaction(
                user_id=user.id,
                amount=-credits_cost,
                transaction_type='samsung_frp_order',
                description=f'Samsung FRP order: {order_id} (Android {android_version})'
            )
            db.session.add(transaction)
            
            # Increment command counter
            command_count = increment_command_count(user.id)
            
            db.session.commit()
            
            # Log action
            log_system_action(user.id, 'samsung_frp_order', 
                             f'Created order {order_id} for Android {android_version} (Cost: {credits_cost} credits)')
            
            # Print notification
            print(f"\n{'='*60}")
            print(f"📱 NEW SAMSUNG FRP ORDER")
            print(f"Order ID: {order_id}")
            print(f"User: {user.username} ({user.email})")
            print(f"IMEI: {imei}")
            print(f"Android Version: {android_version}")
            print(f"Credits: {credits_cost}")
            print(f"{'='*60}\n")
            
            return jsonify({
                'success': True,
                'order_id': order_id,
                'status': 'pending',
                'credits_deducted': credits_cost,
                'credits_remaining': user.credits,
                'android_version': android_version,
                'message': f'Order created successfully. Admin will process it shortly.',
                'commands_used_today': command_count
            }), 200
            
        except Exception as e:
            db.session.rollback()
            print(f"Error creating Samsung FRP order: {e}")
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500
    
    
    @app.route('/api/samsung/frp/order-status/<order_id>', methods=['GET'])
    @api_login_required
    def samsung_frp_order_status(order_id):
        """Check status of a Samsung FRP order"""
        try:
            user = current_user
            from database import SamsungOrder
            order = SamsungOrder.query.filter_by(order_id=order_id).first()
            
            if not order:
                return jsonify({'success': False, 'error': 'Order not found'}), 404
            
            if order.user_id != user.id and not user.is_admin:
                return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            
            return jsonify({
                'success': True,
                'order_id': order.order_id,
                'status': order.status,
                'android_version': order.android_version,
                'imei': order.imei,
                'credits_cost': order.credits_cost,
                'created_at': order.created_at.isoformat() if order.created_at else None,
                'processed_at': order.processed_at.isoformat() if order.processed_at else None,
                'result_code': order.result_code,
                'result_message': order.result_message,
                'admin_notes': order.admin_notes
            }), 200
            
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    
    
    @app.route('/api/samsung/frp/server-status', methods=['GET'])
    def samsung_frp_server_status():
        """Get Samsung FRP server status (public endpoint)"""
        try:
            from database import ServerStatus
            
            server_status = ServerStatus.query.filter_by(server_name='samsung_frp_server').first()
            
            if server_status and server_status.manual_override:
                server_online = server_status.is_online
            else:
                server_online = check_samsung_frp_server()
            
            return jsonify({
                'success': True,
                'server_online': server_online,
                'service_name': 'Samsung FRP Service',
                'supported_versions': ['13', '14', '15', '16'],
                'pricing': SAMSUNG_FRP_PRICES
            }), 200
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500


    # ==================== ADMIN SAMSUNG FRP SERVER CONTROL ENDPOINTS ====================
    
    @app.route('/api/admin/samsung/server/toggle', methods=['POST'])
    @login_required
    def admin_toggle_samsung_server():
        """Admin: Manually toggle Samsung FRP server ON/OFF"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        try:
            data = request.get_json()
            is_online = data.get('is_online', False)
            
            from database import ServerStatus
            server_status = ServerStatus.query.filter_by(server_name='samsung_frp_server').first()
            if not server_status:
                server_status = ServerStatus(server_name='samsung_frp_server')
                db.session.add(server_status)
            
            server_status.is_online = is_online
            server_status.manual_override = True
            server_status.last_check = datetime.utcnow()
            server_status.error_message = f"Manually set to {'ONLINE' if is_online else 'OFFLINE'} by admin {current_user.username}"
            
            db.session.commit()
            
            status_text = "ONLINE" if is_online else "OFFLINE"
            log_system_action(current_user.id, 'toggle_samsung_server', 
                             f'Set Samsung FRP server to {status_text}')
            
            return jsonify({
                'success': True,
                'message': f'Samsung FRP server set to {status_text}',
                'server_online': is_online,
                'manual_override': True
            }), 200
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/admin/samsung/server/auto', methods=['POST'])
    @login_required
    def admin_samsung_auto_check():
        """Admin: Disable manual override and auto-check real server status"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        try:
            from database import ServerStatus
            server_status = ServerStatus.query.filter_by(server_name='samsung_frp_server').first()
            
            if not server_status:
                server_status = ServerStatus(server_name='samsung_frp_server')
                db.session.add(server_status)
            
            # Disable manual override
            server_status.manual_override = False
            
            # Perform auto-check
            try:
                SAMSUNG_FRP_SERVER_URL = os.environ.get('SAMSUNG_FRP_SERVER_URL', 'https://samsung-frp-api.example.com')
                response = requests.get(f"{SAMSUNG_FRP_SERVER_URL}/health", timeout=5)
                is_online = response.status_code == 200
                server_status.is_online = is_online
                server_status.response_time = int(response.elapsed.total_seconds() * 1000) if is_online else 0
                server_status.error_message = f"Auto-check: Server is {'ONLINE' if is_online else 'OFFLINE'}"
            except Exception as e:
                server_status.is_online = False
                server_status.error_message = f"Auto-check failed: {str(e)}"
            
            server_status.last_check = datetime.utcnow()
            db.session.commit()
            
            status_text = "ONLINE" if server_status.is_online else "OFFLINE"
            log_system_action(current_user.id, 'samsung_auto_check', 
                             f'Auto-check performed: Server is {status_text}')
            
            return jsonify({
                'success': True,
                'message': f'Auto-check completed. Server is {status_text}',
                'server_online': server_status.is_online,
                'manual_override': False,
                'response_time': server_status.response_time,
                'error_message': server_status.error_message
            }), 200
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/admin/samsung/server/status', methods=['GET'])
    @login_required
    def admin_samsung_server_status():
        """Admin: Get detailed Samsung FRP server status"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        try:
            from database import ServerStatus
            server_status = ServerStatus.query.filter_by(server_name='samsung_frp_server').first()
            
            if not server_status:
                return jsonify({
                    'success': True,
                    'server_online': False,
                    'manual_override': False,
                    'message': 'Server status not initialized'
                }), 200
            
            return jsonify({
                'success': True,
                'server_online': server_status.is_online,
                'manual_override': server_status.manual_override,
                'last_check': server_status.last_check.isoformat() if server_status.last_check else None,
                'response_time': server_status.response_time,
                'error_message': server_status.error_message,
                'pricing': SAMSUNG_FRP_PRICES,
                'supported_versions': ['13', '14', '15', '16']
            }), 200
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/admin/samsung/server/reset', methods=['POST'])
    @login_required
    def admin_reset_samsung_server():
        """Admin: Reset server status to default"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        try:
            from database import ServerStatus
            server_status = ServerStatus.query.filter_by(server_name='samsung_frp_server').first()
            
            if server_status:
                server_status.is_online = False
                server_status.manual_override = False
                server_status.response_time = 0
                server_status.error_message = f"Reset to default by admin {current_user.username}"
                server_status.last_check = datetime.utcnow()
            else:
                server_status = ServerStatus(server_name='samsung_frp_server', is_online=False, manual_override=False)
                db.session.add(server_status)
            
            db.session.commit()
            
            log_system_action(current_user.id, 'reset_samsung_server', 'Reset Samsung FRP server to default')
            
            return jsonify({
                'success': True,
                'message': 'Server status reset to default',
                'server_online': False,
                'manual_override': False
            }), 200
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
            
            
    # ==================== VERSION CHECK ENDPOINT ====================
    
    @app.route('/api/check-version', methods=['GET'])
    def check_version():
        """Check for latest desktop client version"""
        try:
            # Current version of desktop client
            current_version = request.args.get('version', '0')
            
            # Latest version from server (you can store this in a file or database)
            version_file = os.path.join(BASE_DIR, 'version.json')
            
            if os.path.exists(version_file):
                with open(version_file, 'r') as f:
                    version_data = json.load(f)
            else:
                # Default version info
                version_data = {
                    'latest_version': '1.1.0',
                    'download_url': 'https://my-dolphin-tool-2.onrender.com/download',
                    'changelog': 'Initial release',
                    'force_update': False,
                    'release_date': datetime.now().isoformat()
                }
            
            # Compare versions
            needs_update = version_data['latest_version'] != current_version
            
            return jsonify({
                'success': True,
                'needs_update': needs_update,
                'latest_version': version_data['latest_version'],
                'current_version': current_version,
                'download_url': version_data['download_url'],
                'changelog': version_data.get('changelog', ''),
                'force_update': version_data.get('force_update', False)
            }), 200
            
        except Exception as e:
            print(f"Error in check_version: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

            #apk path
        # ==================== SERVE APK FILE ====================
    @app.route('/AT-TOOL-GUARD.apk')
    def download_apk():
        from flask import send_file
        apk_path = os.path.join(BASE_DIR, 'AT-TOOL-GUARD.apk')
        if os.path.exists(apk_path):
            return send_file(apk_path, mimetype='application/vnd.android.package-archive', as_attachment=True)
        else:
            return jsonify({'error': 'APK not found'}), 404

    
    # ==================== SYNC COMMANDS FROM GITHUB (ADMIN ONLY) ====================
    
    @app.route('/api/admin/sync-commands', methods=['POST'])
    @login_required
    def sync_commands():
        """Admin only: Sync commands from GitHub repository"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        import subprocess
        import shutil
        
        commands_dir = os.path.join(BASE_DIR, 'commands')
        git_repo = "https://github.com/yourusername/dolphin-commands.git"
        
        try:
            # Create backup
            backup_dir = f"{commands_dir}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            if os.path.exists(commands_dir):
                shutil.copytree(commands_dir, backup_dir)
                print(f"📦 Backup created: {backup_dir}")
            
            if os.path.exists(commands_dir):
                # Pull latest
                result = subprocess.run(['git', '-C', commands_dir, 'pull'], 
                                       capture_output=True, text=True, timeout=60)
                message = result.stdout or result.stderr
            else:
                # Clone repository
                result = subprocess.run(['git', 'clone', git_repo, commands_dir], 
                                       capture_output=True, text=True, timeout=120)
                message = result.stdout or result.stderr
            
            # Validate JSON files after sync
            for root, dirs, files in os.walk(commands_dir):
                for file in files:
                    if file.endswith('.json'):
                        filepath = os.path.join(root, file)
                        try:
                            with open(filepath, 'r') as f:
                                json.load(f)
                            print(f"✅ Validated: {file}")
                        except json.JSONDecodeError as e:
                            print(f"❌ Invalid JSON in {file}: {e}")
            
            log_system_action(current_user.id, 'sync_commands', 'Commands synced from GitHub')
            
            return jsonify({'success': True, 'message': 'Commands synced successfully', 'details': message})
            
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    
        # ==================== CREATE VERSION FILE (ADMIN ONLY) ====================
    
    @app.route('/api/admin/update-version', methods=['POST'])
    @login_required
    def update_version():
        """Admin only: Update the latest version info"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        latest_version = data.get('latest_version')
        download_url = data.get('download_url')
        changelog = data.get('changelog', '')
        force_update = data.get('force_update', False)
        
        if not latest_version:
            return jsonify({'error': 'latest_version required'}), 400
        
        version_data = {
            'latest_version': latest_version,
            'download_url': download_url or 'https://my-dolphin-tool-2.onrender.com/download',
            'changelog': changelog,
            'force_update': force_update,
            'release_date': datetime.now().isoformat()
        }
        
        version_file = os.path.join(BASE_DIR, 'version.json')
        with open(version_file, 'w') as f:
            json.dump(version_data, f, indent=2)
        
        log_system_action(current_user.id, 'update_version', f'Updated latest version to {latest_version}')
        
        return jsonify({'success': True, 'message': f'Version updated to {latest_version}'})

            # ═══════════════════════════════════════════════════════════
    #  OTP MANAGEMENT API - FORWARDS TO GSM MANAGER
    # ═══════════════════════════════════════════════════════════
    
    OTP_TYPES = {
        # OPPO/OnePlus Services (Your price in credits)
        'oppo_flash': {'name': 'OPPO Flash OTP', 'cost': 35},
        'oneplus': {'name': 'OnePlus OTP', 'cost': 20},
        'oplus_pro': {'name': 'OPLUS Pro OTP', 'cost': 35},
        
        # Realme Services
        'realme_frp': {'name': 'Realme MTK One Click FRP Reset', 'cost': 12},
        'realme_mtk': {'name': 'Realme MTK OTP', 'cost': 12},
        
        # Tecno/Infinix/iTel AntiCrack
        'tecno_anticrack': {'name': 'Tecno/Infinix/iTel Loader AntiCrack', 'cost': 18},
        'tecno_anticrack_p7': {'name': 'Tecno/Infinix/iTel AntiCrack P7', 'cost': 18},
        
        # Tecno/Infinix/iTel Auth Flash
        'tecno_auth_mtk': {'name': 'Tecno/Infinix/iTel Loader Auth Flash', 'cost': 16},
        'infinix_auth_mtk': {'name': 'Infinix Auth Flash MTK', 'cost': 16},
        'tecno_auth_spd': {'name': 'Tecno/Infinix/iTel Auth Flash SPD', 'cost': 16},
        'tecno_cpid': {'name': 'Tecno/Infinix/iTel CPID', 'cost': 25},
        
        # Xiaomi Services
        'xiaomi_frp': {'name': 'Xiaomi FRP One Click', 'cost': 10},
        'xiaomi_otp': {'name': 'Xiaomi OTP', 'cost': 10},
    }

    from database import StoredOTP

    # ── ADMIN: OTP Stats (Now shows GSM Manager as provider) ──
    @app.route('/api/admin/otps/stats', methods=['GET'])
    @login_required
    def admin_otp_stats():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Return provider info instead of local OTP stats
        return jsonify({
            'success': True,
            'provider': 'GSM Manager',
            'provider_url': GSM_API_URL,
            'message': 'OTPs are now provided by GSM Manager in real-time. No local OTP storage needed.',
            'otp_types': OTP_TYPES,
            'summary': {
                'total_available': 'Unlimited (Real-time from provider)',
                'total_used': 'N/A (Tracked via transactions)'
            }
        })

    # ── ADMIN: List OTPs (Deprecated - show message) ──
    @app.route('/api/admin/otps/list', methods=['GET'])
    @login_required
    def admin_otp_list():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        return jsonify({
            'success': False,
            'error': 'This endpoint is deprecated. OTPs are now provided by GSM Manager in real-time.',
            'message': 'No local OTP storage needed. All OTPs are generated on-demand.',
            'provider': 'GSM Manager'
        }), 410

    # ── ADMIN: Used History (Shows transaction history) ──
    @app.route('/api/admin/otps/used-history', methods=['GET'])
    @login_required
    def admin_otp_used_history():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Return transaction history instead
        transactions = CreditTransaction.query.filter_by(transaction_type='otp_purchase').order_by(CreditTransaction.created_at.desc()).limit(50).all()
        
        history = []
        for t in transactions:
            user = User.query.get(t.user_id)
            history.append({
                'id': t.id,
                'otp_type': 'N/A',
                'otp_name': t.description[:50],
                'cost': abs(t.amount),
                'used_by': user.username if user else '?',
                'used_by_email': user.email if user else '?',
                'used_at': t.created_at.isoformat() if t.created_at else None
            })
        
        return jsonify({'success': True, 'history': history, 'total': len(history), 'source': 'credit_transactions'})

    # ── ADMIN: Delete OTP (Deprecated) ──
    @app.route('/api/admin/otps/delete/<int:otp_id>', methods=['DELETE'])
    @login_required
    def admin_delete_otp(otp_id):
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        return jsonify({
            'success': False,
            'error': 'This endpoint is deprecated. OTPs are now provided by GSM Manager.',
            'message': 'No local OTPs to delete.'
        }), 410


    # ── USER: Request OTP (FORWARDS TO GSM MANAGER) ──
    @app.route('/api/user/otps/request', methods=['POST'])
    @api_login_required
    def user_request_otp():
        """
        Request OTP - Forwards to GSM Manager API
        Uses YOUR pricing from OTP_TYPES
        """
        db_session = db.session
        user = current_user
        
        # ========== VALIDATION (Your existing checks) ==========
        if is_maintenance_mode():
            return jsonify({'success': False, 'error': 'Server under maintenance', 'code': 'MAINTENANCE_MODE'}), 503
        
        if user.is_banned:
            return jsonify({'success': False, 'error': 'Account is banned', 'code': 'ACCOUNT_BANNED', 'is_banned': True}), 403
        
        if not user.is_license_valid():
            return jsonify({'success': False, 'error': 'License has expired', 'code': 'LICENSE_EXPIRED', 'license_expired': True}), 403
        
        allowed, cmd_count, cmd_remaining = check_command_limit(user.id)
        if not allowed:
            return jsonify({'success': False, 'error': f'Daily limit reached ({cmd_count}/100)', 'code': 'COMMAND_LIMIT_REACHED'}), 429
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No JSON data'}), 400
        
        otp_type = data.get('otp_type', '').strip().lower()
        model = data.get('model', '').strip()
        imei = data.get('imei', '').strip()
        
        if not otp_type or otp_type not in OTP_TYPES:
            return jsonify({
                'success': False, 
                'error': f'Invalid OTP type', 
                'valid_types': list(OTP_TYPES.keys())
            }), 400
        
        # Get YOUR pricing (what user pays in credits)
        otp_info = OTP_TYPES[otp_type]
        cost = otp_info['cost']
        otp_name = otp_info['name']
        user_credits = user.credits or 0
        
        if user_credits < cost:
            return jsonify({
                'success': False, 
                'error': f'Need {cost} credits. You have {user_credits}', 
                'code': 'INSUFFICIENT_CREDITS', 
                'credits_needed': cost, 
                'credits_available': user_credits
            }), 403
        
        # ========== FORWARD TO GSM MANAGER ==========
        
        gsm = GSMManagerOTPProvider()
        result = gsm.generate_otp(otp_type, model, imei)
        
        print(f"📡 [GSM] User: {user.username}, Type: {otp_type}, Success: {result.get('success')}")
        
        if not result.get('success'):
            log_system_action(user.id, 'otp_provider_error', 
                             f'GSM Manager failed for {otp_name}: {result.get("error")}')
            
            return jsonify({
                'success': False,
                'error': result.get('error', 'Service temporarily unavailable'),
                'code': 'PROVIDER_ERROR',
                'credits_not_deducted': True
            }), 503
        
        # If OTP is pending (still processing)
        if result.get('pending'):
            return jsonify({
                'success': False,
                'pending': True,
                'order_id': result.get('order_id'),
                'delivery': result.get('delivery', 'minutes'),
                'message': result.get('message', 'Order placed. Please check status later.'),
                'check_url': f'/api/otp/status/{result.get("order_id")}',
                'credits_not_deducted': True
            }), 202
        
        # ========== SUCCESS - DEDUCT CREDITS AND RETURN OTP ==========
        
        try:
            # Deduct credits from user (YOUR price)
            user.credits = user_credits - cost
            
            # Create transaction record (metadata only, NO OTP stored)
            transaction = CreditTransaction(
                user_id=user.id, 
                amount=-cost, 
                transaction_type='otp_purchase',
                description=f'Purchased {otp_name} from GSM Manager (Order: {result.get("order_id")})'
            )
            db_session.add(transaction)
            
            # Increment command counter
            new_count = increment_command_count(user.id)
            
            # Log successful purchase
            log_system_action(user.id, 'otp_purchase', 
                             f'Purchased {otp_name} from GSM Manager for {cost} credits')
            
            db_session.commit()
            
            print(f"✅ [GSM] Success - User: {user.username}, OTP: {otp_name}, Cost: {cost} credits")
            
            # Return OTP to user
            return jsonify({
                'success': True,
                'otp_code': result.get('otp_code'),
                'otp_type': otp_type,
                'otp_name': otp_name,
                'cost': cost,
                'credits_remaining': user.credits,
                'commands_used_today': new_count,
                'order_id': result.get('order_id'),
                'provider': 'gsm_manager',
                'delivery': result.get('delivery', 'instant'),
                'usage_note': '⚠️ Save this code now! It will NOT be shown again.'
            }), 200
            
        except Exception as e:
            db_session.rollback()
            print(f"❌ [GSM] Transaction failed: {e}")
            traceback.print_exc()
            
            return jsonify({
                'success': False, 
                'error': 'Transaction failed. No credits deducted.', 
                'code': 'TRANSACTION_FAILED'
            }), 500


    # ── USER: OTP History (Shows transaction history) ──
    @app.route('/api/user/otps/history', methods=['GET'])
    @api_login_required
    def user_otp_history():
        # Get OTP purchases from credit transactions
        purchases = CreditTransaction.query.filter_by(
            user_id=current_user.id, 
            transaction_type='otp_purchase'
        ).order_by(CreditTransaction.created_at.desc()).limit(50).all()
        
        history = []
        for p in purchases:
            history.append({
                'id': p.id,
                'type': 'otp_purchase',
                'name': p.description[:50],
                'cost': abs(p.amount),
                'used_at': p.created_at.isoformat() if p.created_at else None
            })
        
        return jsonify({
            'success': True, 
            'history': history, 
            'total': len(history), 
            'total_spent': sum(abs(p.amount) for p in purchases),
            'provider': 'GSM Manager'
        })


    # ── Check Pending OTP Status (New endpoint) ──
    @app.route('/api/otp/status/<order_id>', methods=['GET'])
    @api_login_required
    def check_pending_otp(order_id):
        """Check status of pending OTP order from GSM Manager"""
        
        gsm = GSMManagerOTPProvider()
        result = gsm.check_order_status(order_id)
        
        if result.get('success'):
            if result.get('otp_code'):
                return jsonify({
                    'success': True,
                    'ready': True,
                    'otp_code': result.get('otp_code'),
                    'status': result.get('status'),
                    'order_id': order_id
                })
            else:
                return jsonify({
                    'success': True,
                    'ready': False,
                    'status': result.get('status'),
                    'message': 'OTP is still being processed. Please check again in a few moments.'
                })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Unknown error')
            }), 500


    #  AUTO-FIX: Ensure OTP constraint exists
    # ═══════════════════════════════════════════════════════════
    @app.before_request
    def _ensure_otp_constraint():
        """Run once to fix credit_transactions constraint for OTP purchases"""
        if not getattr(app, '_otp_constraint_fixed', False):
            try:
                from sqlalchemy import text
                db.session.execute(text("ALTER TABLE credit_transactions DROP CONSTRAINT IF EXISTS check_transaction_type"))
                db.session.execute(text("ALTER TABLE credit_transactions DROP CONSTRAINT IF EXISTS credit_transactions_transaction_type_check"))
                db.session.commit()
            except:
                db.session.rollback()
            try:
                db.session.execute(text("""
                    ALTER TABLE credit_transactions ADD CONSTRAINT check_transaction_type 
                    CHECK (transaction_type IN (
                        'admin_add','admin_deduct','purchase','usage','refund','commission',
                        'device_reset','pc_change','device_registration','credit_used','hwid_reset',
                        'otp_purchase','samsung_frp_order','reseller_gift'
                    ))
                """))
                db.session.commit()
                print("✅ Credit transaction constraint updated with reseller_gift")
            except Exception as e:
                db.session.rollback()
                print(f"⚠️ Credit transaction constraint: {e}")
            app._otp_constraint_fixed = True

    # ==================== SECURITY ENDPOINTS FOR ANTI-TAMPERING ====================

    @app.route('/api/security/challenge', methods=['POST'])
    def create_security_challenge():
        """Create a cryptographic challenge for client verification"""
        try:
            if is_maintenance_mode():
                return jsonify({'error': 'Server under maintenance'}), 503
            
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No JSON data'}), 400
            
            session_token = data.get('session_token', '')
            
            if not session_token:
                return jsonify({'error': 'Session token required'}), 400
            
            session_obj = UserSession.query.filter_by(
                session_token=session_token,
                is_active=True
            ).filter(UserSession.expires_at > datetime.utcnow()).first()
            
            if not session_obj:
                return jsonify({'error': 'Invalid or expired session'}), 401
            
            user = User.query.get(session_obj.user_id)
            if not user or user.is_banned:
                return jsonify({'error': 'User not found or banned'}), 401
            
            challenge = secrets.token_hex(32)
            challenge_id = secrets.token_hex(16)
            expiry = datetime.utcnow() + timedelta(seconds=60)
            
            from sqlalchemy import text
            db.session.execute(text("""
                INSERT INTO security_challenges (challenge_id, challenge, user_id, expires_at, used)
                VALUES (:challenge_id, :challenge, :user_id, :expires_at, FALSE)
            """), {
                'challenge_id': challenge_id,
                'challenge': challenge,
                'user_id': user.id,
                'expires_at': expiry
            })
            db.session.commit()
            
            print(f"🔐 Challenge created for user {user.username}: {challenge_id[:16]}...")
            
            return jsonify({
                'success': True,
                'challenge_id': challenge_id,
                'challenge': challenge,
                'expiry': 60
            }), 200
            
        except Exception as e:
            db.session.rollback()
            print(f"Error in create_security_challenge: {e}")
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/security/verify-challenge', methods=['POST'])
    def verify_security_challenge():
        """Verify client's response to cryptographic challenge"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No JSON data'}), 400
            
            challenge_id = data.get('challenge_id', '')
            client_response = data.get('response', '')
            session_token = data.get('session_token', '')
            device_fingerprint = data.get('device_fingerprint', '')
            
            if not challenge_id or not client_response:
                return jsonify({'error': 'Challenge ID and response required'}), 400
            
            from sqlalchemy import text
            
            challenge_row = db.session.execute(text("""
                SELECT challenge, user_id, expires_at, used 
                FROM security_challenges 
                WHERE challenge_id = :challenge_id
            """), {'challenge_id': challenge_id}).fetchone()
            
            if not challenge_row:
                return jsonify({'error': 'Challenge not found'}), 404
            
            challenge = challenge_row[0]
            user_id = challenge_row[1]
            expires_at = datetime.fromisoformat(challenge_row[2]) if isinstance(challenge_row[2], str) else challenge_row[2]
            used = challenge_row[3]
            
            if expires_at < datetime.utcnow():
                db.session.execute(text("DELETE FROM security_challenges WHERE challenge_id = :challenge_id"), 
                                 {'challenge_id': challenge_id})
                db.session.commit()
                return jsonify({'error': 'Challenge expired'}), 401
            
            if used:
                return jsonify({'error': 'Challenge already used'}), 401
            
            session_obj = UserSession.query.filter_by(
                session_token=session_token,
                is_active=True
            ).filter(UserSession.expires_at > datetime.utcnow()).first()
            
            if not session_obj or session_obj.user_id != user_id:
                return jsonify({'error': 'Invalid session'}), 401
            
            user = User.query.get(user_id)
            if not user:
                return jsonify({'error': 'User not found'}), 401
            
            expected_private_key_seed = hashlib.sha512(f"{device_fingerprint}:{user.email}:dolphin_bypass_key_v2".encode()).digest()
            expected_private_key = base64.b64encode(expected_private_key_seed).decode()
            
            expected_response = hashlib.sha512(
                f"{challenge}:{expected_private_key}:{device_fingerprint}".encode()
            ).hexdigest()
            
            db.session.execute(text("""
                INSERT INTO challenge_logs (user_id, challenge_id, success, device_fingerprint, ip_address)
                VALUES (:user_id, :challenge_id, :success, :fingerprint, :ip)
            """), {
                'user_id': user.id,
                'challenge_id': challenge_id,
                'success': client_response == expected_response,
                'fingerprint': device_fingerprint,
                'ip': get_real_ip()
            })
            
            if client_response == expected_response:
                db.session.execute(text("""
                    UPDATE security_challenges SET used = TRUE 
                    WHERE challenge_id = :challenge_id
                """), {'challenge_id': challenge_id})
                db.session.commit()
                print(f"✅ Challenge verified for user {user.username}")
                return jsonify({'success': True, 'verified': True}), 200
            else:
                db.session.commit()
                print(f"❌ Challenge verification failed for user {user.username}")
                return jsonify({'error': 'Invalid challenge response'}), 401
                
        except Exception as e:
            db.session.rollback()
            print(f"Error in verify_security_challenge: {e}")
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/security/tamper-report', methods=['POST'])
    def handle_tamper_report():
        """Receive and process tamper detection reports from client with 3-strike auto-ban"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No JSON data'}), 400
            
            tamper_flags = data.get('tamper_flags', [])
            email = data.get('email', '')
            device_fingerprint = data.get('device_fingerprint', '')
            ip = data.get('ip', get_real_ip())
            username = data.get('username', 'Unknown')
            hostname = data.get('hostname', 'Unknown')
            
            if not email:
                return jsonify({'error': 'Email required'}), 400
            
            from sqlalchemy import text
            
            flags_json = json.dumps(tamper_flags)
            db.session.execute(text("""
                INSERT INTO tamper_reports (email, device_fingerprint, tamper_flags, ip_address, username, hostname)
                VALUES (:email, :fingerprint, :flags, :ip, :username, :hostname)
            """), {
                'email': email,
                'fingerprint': device_fingerprint,
                'flags': flags_json,
                'ip': ip,
                'username': username,
                'hostname': hostname
            })
            
            db.session.execute(text("""
                INSERT INTO tamper_counters (email, tamper_count, last_tamper_at)
                VALUES (:email, 1, :now)
                ON CONFLICT(email) DO UPDATE SET
                    tamper_count = tamper_count + 1,
                    last_tamper_at = :now
            """), {'email': email, 'now': datetime.utcnow()})
            
            db.session.commit()
            
            count_row = db.session.execute(text("SELECT tamper_count FROM tamper_counters WHERE email = :email"), 
                                           {'email': email}).fetchone()
            tamper_count = count_row[0] if count_row else 0
            
            # MAX TAMPER ATTEMPTS = 3
            MAX_TAMPER_ATTEMPTS = 3
            BAN_DURATION_HOURS = 24
            
            print(f"\n{'='*70}")
            print(f"🚨 TAMPER DETECTED!")
            print(f"   Email: {email}")
            print(f"   Username: {username}")
            print(f"   Flags: {', '.join(tamper_flags)}")
            print(f"   IP: {ip}")
            print(f"   Count: {tamper_count}/{MAX_TAMPER_ATTEMPTS}")
            print(f"{'='*70}\n")
            
            user = User.query.filter_by(email=email).first()
            is_banned = False
            ban_until = None
            
            if tamper_count >= MAX_TAMPER_ATTEMPTS and user and not user.is_banned:
                # Auto-ban the user
                user.is_banned = True
                user.ban_reason = f"Auto-banned after {tamper_count} tampering attempts"
                user.ban_type = 'auto'
                user.tamper_attempt_count = tamper_count
                user.last_tamper_at = datetime.utcnow()
                user.suspended_until = datetime.utcnow() + timedelta(hours=BAN_DURATION_HOURS)
                
                db.session.execute(text("""
                    UPDATE tamper_counters SET 
                        banned_at = :now, 
                        ban_reason = :reason
                    WHERE email = :email
                """), {
                    'now': datetime.utcnow(),
                    'reason': user.ban_reason,
                    'email': email
                })
                
                UserSession.query.filter_by(user_id=user.id, is_active=True).update({'is_active': False})
                db.session.commit()
                is_banned = True
                ban_until = user.suspended_until
                
                log_system_action(user.id, 'auto_ban', 
                                f'User auto-banned after {tamper_count} tampering attempts')
                
                print(f"🔨 USER AUTO-BANNED: {email} after {tamper_count} attempts")
            
            remaining_attempts = max(0, MAX_TAMPER_ATTEMPTS - tamper_count)
            
            return jsonify({
                'success': True,
                'received': True,
                'tamper_count': tamper_count,
                'max_attempts': MAX_TAMPER_ATTEMPTS,
                'remaining_attempts': remaining_attempts,
                'warning': remaining_attempts <= 1,
                'banned': is_banned or (tamper_count >= MAX_TAMPER_ATTEMPTS),
                'ban_until': ban_until.isoformat() if ban_until else None
            }), 200
            
        except Exception as e:
            db.session.rollback()
            print(f"Error in handle_tamper_report: {e}")
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/security/check-ban', methods=['POST'])
    def check_ban_status():
        """Check if a user/device is banned"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No JSON data'}), 400
            
            email = data.get('email', '')
            device_fingerprint = data.get('device_fingerprint', '')
            
            if not email:
                return jsonify({'error': 'Email required'}), 400
            
            user = User.query.filter_by(email=email).first()
            
            if not user:
                return jsonify({
                    'success': True,
                    'banned': False,
                    'exists': False
                }), 200
            
            if user.is_banned:
                ban_until = None
                
                # Check if ban has expired
                if user.suspended_until and user.suspended_until < datetime.utcnow():
                    # Auto-unban after expiry
                    user.is_banned = False
                    user.ban_reason = None
                    user.suspended_until = None
                    
                    # Reset tamper counter
                    from sqlalchemy import text
                    db.session.execute(text("""
                        UPDATE tamper_counters SET 
                            tamper_count = 0,
                            banned_at = NULL,
                            ban_reason = NULL
                        WHERE email = :email
                    """), {'email': email})
                    
                    db.session.commit()
                    
                    log_system_action(user.id, 'auto_unban', 'User auto-unbanned after ban expiry')
                    
                    return jsonify({
                        'success': True,
                        'banned': False,
                        'message': 'Ban has expired'
                    }), 200
                else:
                    ban_until = user.suspended_until
                
                # Get violation count
                from sqlalchemy import text
                result = db.session.execute(text(
                    "SELECT tamper_count FROM tamper_counters WHERE email = :email"
                ), {'email': email}).fetchone()
                
                violation_count = result[0] if result else 0
                
                return jsonify({
                    'success': True,
                    'banned': True,
                    'ban_until': ban_until.isoformat() if ban_until else None,
                    'ban_reason': user.ban_reason,
                    'violation_count': violation_count,
                    'remaining_hours': int((ban_until - datetime.utcnow()).total_seconds() / 3600) if ban_until else 0
                }), 200
            
            return jsonify({
                'success': True,
                'banned': False,
                'exists': True
            }), 200
            
        except Exception as e:
            print(f"Error in check_ban_status: {e}")
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/security/health', methods=['GET'])
    def security_health():
        """Security system health check endpoint"""
        return jsonify({
            'status': 'operational',
            'challenge_expiry': 60,
            'max_tamper_attempts': 3,
            'ban_duration_hours': 24,
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    @app.route('/api/security/report-violation', methods=['POST'])
    def handle_violation_report():
        """Receive and process security violation reports from client with auto-ban"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No JSON data'}), 400
            
            # Extract data
            email = data.get('email', '')
            device_fingerprint = data.get('device_fingerprint', '')
            violation_type = data.get('violation_type', 'UNKNOWN')
            timestamp = data.get('timestamp', datetime.now().isoformat())
            violation_count = data.get('violation_count', 0)
            details = data.get('details', {})
            username = data.get('username', 'Unknown')
            hostname = data.get('hostname', 'Unknown')
            ip = data.get('ip', get_real_ip())
            
            if not email:
                return jsonify({'error': 'Email required'}), 400
            
            # ========== CHECK FOR EXISTING BAN ==========
            from sqlalchemy import text
            
            # Check if user is already banned
            user = User.query.filter_by(email=email).first()
            if user and user.is_banned:
                ban_until = user.suspended_until
                return jsonify({
                    'success': False,
                    'error': 'User is already banned',
                    'banned': True,
                    'ban_reason': user.ban_reason or 'Security violation',
                    'ban_until': ban_until.isoformat() if ban_until else None
                }), 403
            
            # ========== STORE VIOLATION REPORT ==========
            flags_json = json.dumps({
                'violation_type': violation_type,
                'details': details,
                'timestamp': timestamp
            })
            
            db.session.execute(text("""
                INSERT INTO tamper_reports (email, device_fingerprint, tamper_flags, ip_address, username, hostname)
                VALUES (:email, :fingerprint, :flags, :ip, :username, :hostname)
            """), {
                'email': email,
                'fingerprint': device_fingerprint,
                'flags': flags_json,
                'ip': ip,
                'username': username,
                'hostname': hostname
            })
            
            # ========== UPDATE VIOLATION COUNTER ==========
            result = db.session.execute(text("""
                INSERT INTO tamper_counters (email, tamper_count, last_tamper_at)
                VALUES (:email, 1, :now)
                ON CONFLICT(email) DO UPDATE SET
                    tamper_count = tamper_count + 1,
                    last_tamper_at = :now
                RETURNING tamper_count
            """), {'email': email, 'now': datetime.utcnow()})
            
            tamper_count = result.fetchone()[0] if result.rowcount > 0 else 1
            
            # ========== AUTO-BAN LOGIC ==========
            MAX_VIOLATIONS = 3
            BAN_DURATION_HOURS = 24
            
            is_banned = False
            ban_until = None
            
            if tamper_count >= MAX_VIOLATIONS and user and not user.is_banned:
                # Auto-ban the user
                user.is_banned = True
                user.ban_reason = f"Auto-banned after {tamper_count} security violations"
                user.ban_type = 'auto'
                user.tamper_attempt_count = tamper_count
                user.last_tamper_at = datetime.utcnow()
                user.suspended_until = datetime.utcnow() + timedelta(hours=BAN_DURATION_HOURS)
                
                # Update tamper counter
                db.session.execute(text("""
                    UPDATE tamper_counters SET 
                        banned_at = :now, 
                        ban_reason = :reason
                    WHERE email = :email
                """), {
                    'now': datetime.utcnow(),
                    'reason': user.ban_reason,
                    'email': email
                })
                
                # Invalidate all sessions
                UserSession.query.filter_by(user_id=user.id, is_active=True).update({'is_active': False})
                
                db.session.commit()
                is_banned = True
                ban_until = user.suspended_until
                
                # Log the ban
                log_system_action(user.id, 'auto_ban', 
                                f'User auto-banned after {tamper_count} security violations')
                
                print(f"\n{'='*70}")
                print(f"🔨 USER AUTO-BANNED!")
                print(f"   Email: {email}")
                print(f"   Violations: {tamper_count}/{MAX_VIOLATIONS}")
                print(f"   Ban Duration: {BAN_DURATION_HOURS} hours")
                print(f"{'='*70}\n")
            
            db.session.commit()
            
            remaining_attempts = max(0, MAX_VIOLATIONS - tamper_count)
            
            return jsonify({
                'success': True,
                'violation_count': tamper_count,
                'max_violations': MAX_VIOLATIONS,
                'remaining_attempts': remaining_attempts,
                'banned': is_banned,
                'ban_until': ban_until.isoformat() if ban_until else None,
                'warning': remaining_attempts <= 1
            }), 200
            
        except Exception as e:
            db.session.rollback()
            print(f"Error in handle_violation_report: {e}")
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

    # ==================== ADMIN SECURITY ENDPOINTS ====================

    @app.route('/api/admin/security/tamper-reports', methods=['GET'])
    @login_required
    def admin_tamper_reports():
        """Admin: View all tamper reports with ban reasons"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        try:
            from sqlalchemy import text
            
            filter_status = request.args.get('status', 'all')
            page = int(request.args.get('page', 1))
            limit = int(request.args.get('limit', 50))
            offset = (page - 1) * limit
            
            query = """
                SELECT 
                    tr.*, 
                    tc.tamper_count, 
                    tc.banned_at, 
                    tc.ban_reason,
                    u.is_banned,
                    u.ban_reason as user_ban_reason,
                    u.ban_type,
                    u.username
                FROM tamper_reports tr
                LEFT JOIN tamper_counters tc ON tr.email = tc.email
                LEFT JOIN users u ON tr.email = u.email
                WHERE 1=1
            """
            params = {}
            
            if filter_status == 'banned':
                query += " AND u.is_banned = TRUE"
            elif filter_status == 'warning':
                query += " AND tc.tamper_count >= 2 AND (u.is_banned = FALSE OR u.is_banned IS NULL)"
            
            query += " ORDER BY tr.reported_at DESC LIMIT :limit OFFSET :offset"
            params['limit'] = limit
            params['offset'] = offset
            
            reports = db.session.execute(text(query), params).fetchall()
            
            reports_data = []
            for report in reports:
                flags = json.loads(report[3]) if report[3] else []
                reports_data.append({
                    'id': report[0],
                    'email': report[1],
                    'device_fingerprint': report[2][:32] + '...' if report[2] and len(report[2]) > 32 else report[2],
                    'tamper_flags': flags,
                    'ip_address': report[4],
                    'username': report[5] or (report[15] if len(report) > 15 else 'Unknown'),
                    'hostname': report[6],
                    'reported_at': report[7].isoformat() if report[7] else None,
                    'tamper_count': report[8] if len(report) > 8 else 0,
                    'banned_at': report[9].isoformat() if len(report) > 9 and report[9] else None,
                    'is_banned': bool(report[11]) if len(report) > 11 else False,
                    'ban_reason': report[12] if len(report) > 12 else None,
                    'ban_type': report[13] if len(report) > 13 else 'manual'
                })
            
            stats = db.session.execute(text("""
                SELECT 
                    COUNT(DISTINCT tr.email) as unique_users,
                    SUM(CASE WHEN u.is_banned = TRUE THEN 1 ELSE 0 END) as banned_users,
                    AVG(tc.tamper_count) as avg_attempts
                FROM tamper_reports tr
                LEFT JOIN tamper_counters tc ON tr.email = tc.email
                LEFT JOIN users u ON tr.email = u.email
            """)).fetchone()
            
            return jsonify({
                'success': True,
                'reports': reports_data,
                'total': len(reports_data),
                'stats': {
                    'unique_users': stats[0] or 0,
                    'banned_users': stats[1] or 0,
                    'avg_attempts': round(stats[2] or 0, 2)
                }
            }), 200
            
        except Exception as e:
            print(f"Error in admin_tamper_reports: {e}")
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/security/reset-public-key', methods=['POST'])
    @login_required
    def admin_reset_public_key():
        """Admin: Reset user's public key (clears device binding)"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No JSON data'}), 400
            
            user_id = data.get('user_id')
            email = data.get('email')
            
            if not user_id and not email:
                return jsonify({'error': 'User ID or email required'}), 400
            
            user = None
            if user_id:
                user = User.query.get(user_id)
            elif email:
                user = User.query.filter_by(email=email).first()
            
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            user.bound_hwid_hash = None
            user.bound_pc_manufacturer = None
            user.bound_windows_version = None
            user.bound_hardware_fingerprint = None
            user.bound_system_info = None
            user.bound_ip_address = None
            user.bound_at = None
            user.last_verified_at = None
            user.is_verified_device = False
            user.verification_failures = 0
            
            Device.query.filter_by(user_id=user.id, is_active=True).update({'is_active': False})
            UserSession.query.filter_by(user_id=user.id, is_active=True).update({'is_active': False})
            
            db.session.commit()
            
            log_system_action(current_user.id, 'reset_public_key', 
                             f'Reset device binding for user {user.username}')
            
            return jsonify({
                'success': True,
                'message': f'Public key/device binding reset for user {user.username}',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email
                }
            }), 200
            
        except Exception as e:
            db.session.rollback()
            print(f"Error in admin_reset_public_key: {e}")
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/security/unban-user', methods=['POST'])
    @login_required
    def admin_unban_user():
        """Admin: Unban a user who was banned due to tampering"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No JSON data'}), 400
            
            user_id = data.get('user_id')
            email = data.get('email')
            
            if not user_id and not email:
                return jsonify({'error': 'User ID or email required'}), 400
            
            user = None
            if user_id:
                user = User.query.get(user_id)
            elif email:
                user = User.query.filter_by(email=email).first()
            
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            if not user.is_banned:
                return jsonify({'error': 'User is not banned'}), 400
            
            user.is_banned = False
            user.ban_reason = None
            user.suspended_until = None
            user.failed_login_count = 0
            
            db.session.commit()
            
            log_system_action(current_user.id, 'unban_user', f'Unbanned user {user.username}')
            
            return jsonify({
                'success': True,
                'message': f'User {user.username} has been unbanned',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_banned': user.is_banned
                }
            }), 200
            
        except Exception as e:
            db.session.rollback()
            print(f"Error in admin_unban_user: {e}")
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/security/challenge-logs', methods=['GET'])
    @login_required
    def admin_challenge_logs():
        """Admin: View all challenge verification logs (success/failure)"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        try:
            from sqlalchemy import text
            
            filter_type = request.args.get('filter', 'all')
            page = int(request.args.get('page', 1))
            limit = int(request.args.get('limit', 50))
            offset = (page - 1) * limit
            
            query = """
                SELECT cl.*, u.username, u.email 
                FROM challenge_logs cl
                LEFT JOIN users u ON cl.user_id = u.id
                WHERE 1=1
            """
            params = {}
            
            if filter_type == 'success':
                query += " AND cl.success = TRUE"
            elif filter_type == 'failed':
                query += " AND cl.success = FALSE"
            
            query += " ORDER BY cl.created_at DESC LIMIT :limit OFFSET :offset"
            params['limit'] = limit
            params['offset'] = offset
            
            logs = db.session.execute(text(query), params).fetchall()
            
            stats = db.session.execute(text("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN success = TRUE THEN 1 ELSE 0 END) as successful,
                    SUM(CASE WHEN success = FALSE THEN 1 ELSE 0 END) as failed,
                    COUNT(DISTINCT user_id) as unique_users
                FROM challenge_logs
            """)).fetchone()
            
            logs_data = []
            for log in logs:
                logs_data.append({
                    'id': log[0],
                    'user_id': log[1],
                    'challenge_id': log[2][:16] + '...',
                    'success': bool(log[3]),
                    'device_fingerprint': log[4][:32] + '...' if log[4] and len(log[4]) > 32 else log[4],
                    'ip_address': log[5],
                    'created_at': log[6].isoformat() if log[6] else None,
                    'username': log[7] if len(log) > 7 else None,
                    'email': log[8] if len(log) > 8 else None
                })
            
            return jsonify({
                'success': True,
                'logs': logs_data,
                'total': len(logs_data),
                'stats': {
                    'total_attempts': stats[0] or 0,
                    'successful': stats[1] or 0,
                    'failed': stats[2] or 0,
                    'unique_users': stats[3] or 0,
                    'success_rate': round((stats[1] or 0) / (stats[0] or 1) * 100, 2)
                }
            }), 200
            
        except Exception as e:
            print(f"Error in admin_challenge_logs: {e}")
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

            # Add this function to your server code (after the existing security endpoints)

                # ==================== SECURITY CHECK FUNCTION ====================

    def check_client_security(self, user_id, client_security_info):
        """
        Check if client PC has security violations
        Returns: (allowed, block_reason, tamper_count, remaining_attempts)
        """
        from sqlalchemy import text
        
        tamper_flags = client_security_info.get('tamper_flags', [])
        tamper_detected = client_security_info.get('tamper_detected', False)
        device_fingerprint = client_security_info.get('device_fingerprint', '')
        
        # Get user
        user = User.query.get(user_id)
        if not user:
            return False, "User not found", 0, 0
        
        # Check if user is already banned
        if user.is_banned:
            if user.suspended_until and user.suspended_until > datetime.utcnow():
                return False, "Device is banned", 0, 0
            else:
                # Ban expired, unban
                user.is_banned = False
                user.ban_reason = None
                user.suspended_until = None
                db.session.commit()
        
        # If no tampering detected, allow
        if not tamper_detected and not tamper_flags:
            return True, None, 0, 0
        
        # ========== RECORD TAMPERING ==========
        MAX_TAMPER_ATTEMPTS = 3
        
        for flag in tamper_flags:
            # Store tamper report
            db.session.execute(text("""
                INSERT INTO tamper_reports (email, device_fingerprint, tamper_flags, ip_address, username, hostname)
                VALUES (:email, :fingerprint, :flags, :ip, :username, :hostname)
            """), {
                'email': user.email,
                'fingerprint': device_fingerprint or user.device_fingerprint,
                'flags': json.dumps(tamper_flags),
                'ip': get_real_ip(),
                'username': user.username,
                'hostname': platform.node()
            })
        
        # Update tamper counter
        db.session.execute(text("""
            INSERT INTO tamper_counters (email, tamper_count, last_tamper_at)
            VALUES (:email, 1, :now)
            ON CONFLICT(email) DO UPDATE SET
                tamper_count = tamper_count + 1,
                last_tamper_at = :now
        """), {'email': user.email, 'now': datetime.utcnow()})
        
        db.session.commit()
        
        # Get current tamper count
        count_row = db.session.execute(text(
            "SELECT tamper_count FROM tamper_counters WHERE email = :email"
        ), {'email': user.email}).fetchone()
        
        tamper_count = count_row[0] if count_row else 0
        remaining_attempts = max(0, MAX_TAMPER_ATTEMPTS - tamper_count)
        
        # ========== AUTO-BAN IF EXCEEDED ==========
        if tamper_count >= MAX_TAMPER_ATTEMPTS:
            user.is_banned = True
            user.ban_reason = f"Auto-banned after {tamper_count} tampering attempts"
            user.ban_type = 'auto'
            user.suspended_until = datetime.utcnow() + timedelta(hours=24)
            user.tamper_attempt_count = tamper_count
            user.last_tamper_at = datetime.utcnow()
            
            db.session.execute(text("""
                UPDATE tamper_counters SET 
                    banned_at = :now, 
                    ban_reason = :reason
                WHERE email = :email
            """), {
                'now': datetime.utcnow(),
                'reason': user.ban_reason,
                'email': user.email
            })
            
            # Invalidate all sessions
            UserSession.query.filter_by(user_id=user.id, is_active=True).update({'is_active': False})
            db.session.commit()
            
            log_system_action(user.id, 'auto_ban', 
                             f'User auto-banned after {tamper_count} tampering attempts')
            
            return False, "Device banned - 24 hour lockout", tamper_count, 0
        
        # ========== BLOCK COMMAND BUT DON'T BAN YET ==========
        log_system_action(user.id, 'tamper_block', 
                         f'Command blocked - Tampering flags: {", ".join(tamper_flags)}')
        
        return False, f"Security violation detected - {remaining_attempts} attempts remaining", tamper_count, remaining_attempts
        
    return app

app = create_app()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
