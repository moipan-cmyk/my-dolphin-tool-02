"""
Dolphin Bypass Tool - Main Application
Complete rebuilt version with security enhancements, rate limiting, and error handling
"""

import os
import sys
import secrets
import json
import traceback
import re
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, request, flash, redirect, jsonify, render_template, 
    url_for, session as flask_session, send_file
)
from flask_login import LoginManager, login_required, current_user, login_user, logout_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ==================== CONFIGURATION ====================
from config import Config
from database import db, User, Device, UserSession, DeviceHistory, CreditTransaction, SystemLog

# ==================== UTILS IMPORT ====================
from utils import (
    init_encryption, encrypt_data, decrypt_data, encrypted_response, encrypted_request,
    log_system as log_system_action, get_real_ip, get_user_agent, hash_hwid,
    success_response, error_response, validate_email, validate_password,
    get_days_remaining, deduct_credits, add_credits, log_device_history,
    get_next_admission_number, get_user_by_identifier, get_command_cost
)

# ==================== CONSTANTS ====================
SESSION_DURATION_HOURS = 12
DEVICE_RESET_COST = 2
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

print("\n" + "="*60)
print("🔐 Starting Dolphin Bypass Tool Server")
print("="*60)

# ==================== INITIALIZE EXTENSIONS ====================
login_manager = LoginManager()

# ==================== HELPER FUNCTIONS ====================
def get_user_from_token():
    """Extract user from session token"""
    session_token = None
    
    # Check Authorization header
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        session_token = auth_header.split(' ')[1]
    
    # Check JSON body
    if not session_token and request.is_json:
        data = request.get_json(silent=True)
        if data:
            session_token = data.get('session_token')
    
    # Check query params
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

def validate_password_strength(password):
    """Enhanced password validation"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    return True, "Password is strong"

def sanitize_input(value, max_length=None):
    """Sanitize user input"""
    if value is None:
        return None
    value = str(value).strip()
    if max_length:
        value = value[:max_length]
    return value

def validate_path_safety(filepath, base_directory):
    """Ensure path is within base directory"""
    real_path = os.path.realpath(filepath)
    real_base = os.path.realpath(base_directory)
    return real_path.startswith(real_base)

# ==================== DECORATORS ====================
def api_login_required(f):
    """API authentication decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            return f(*args, **kwargs)
        
        user = get_user_from_token()
        if user:
            login_user(user, remember=False)
            return f(*args, **kwargs)
        
        return error_response("Authentication required", 401)
    return decorated_function

def admin_required(f):
    """Admin-only decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return error_response("Authentication required", 401)
        if not current_user.is_admin:
            return error_response("Admin access required", 403)
        return f(*args, **kwargs)
    return decorated_function

# ==================== CREATE APP ====================
def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Security configurations
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(hours=SESSION_DURATION_HOURS),
        MAX_CONTENT_LENGTH=16 * 1024 * 1024  # 16MB max file size
    )
    
    # Proxy fix for proper IP detection
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    
    # Set secret key
    if not app.config.get('SECRET_KEY'):
        app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_urlsafe(32))
        print("⚠️ Using generated SECRET_KEY - set in production!")
    
    # Initialize encryption
    encryption_manager = init_encryption(encryption_type='fernet')
    print("✅ Encryption initialized")
    
    # Initialize rate limiter
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri=app.config.get('RATE_LIMIT_STORAGE', 'memory://')
    )
    
    # Custom key function for authenticated users
    def get_user_rate_limit_key():
        if current_user.is_authenticated:
            return f"user:{current_user.id}"
        return get_remote_address()
    
    # Initialize database
    db.init_app(app)
    
    # Create tables and admin user
    with app.app_context():
        db.create_all()
        print("✅ Database tables verified")
        
        # Create admin user from environment variables
        admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
        admin_password = os.environ.get('ADMIN_PASSWORD')
        
        if admin_password:
            admin = User.query.filter_by(email=admin_email).first()
            if not admin:
                admin = User(
                    username='admin',
                    email=admin_email,
                    admission_number=1000,
                    credits=1000,
                    is_admin=True,
                    is_active=True,
                    device_limit=0,
                    license_expiry_date=datetime.utcnow() + timedelta(days=365*10)
                )
                admin.set_password(admin_password)
                db.session.add(admin)
                db.session.commit()
                print(f"✅ Admin user created: {admin_email}")
            else:
                admin.is_admin = True
                db.session.commit()
                print(f"✅ Admin user verified: {admin_email}")
    
    # Initialize login manager
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = None
    
    @login_manager.user_loader
    def load_user(user_id):
        try:
            return User.query.get(int(user_id))
        except:
            return None
    
    # ==================== EMAIL HELPER ====================
    def send_reset_email(email, reset_token):
        """Send password reset email"""
        try:
            config = app.config
            smtp_server = config.get('SMTP_SERVER', 'smtp.gmail.com')
            smtp_port = config.get('SMTP_PORT', 587)
            smtp_user = config.get('SMTP_USER')
            smtp_password = config.get('SMTP_PASSWORD')
            from_email = config.get('FROM_EMAIL', smtp_user)
            app_name = config.get('APP_NAME', 'Dolphin Bypass Tool')
            base_url = config.get('BASE_URL', 'http://localhost:5000')
            
            reset_link = f"{base_url}/reset-password/{reset_token}"
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Password Reset</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; }}
                    .container {{ max-width: 600px; margin: 40px auto; padding: 30px; background: #ffffff; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                    .header {{ text-align: center; margin-bottom: 30px; }}
                    .header h2 {{ color: #333; }}
                    .content {{ margin-bottom: 30px; }}
                    .button {{ display: inline-block; padding: 12px 30px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; border-radius: 5px; font-weight: bold; }}
                    .footer {{ text-align: center; color: #666; font-size: 12px; margin-top: 30px; }}
                    .warning {{ background: #fff3cd; border: 1px solid #ffeeba; padding: 15px; border-radius: 5px; margin-top: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2>🔐 Password Reset Request</h2>
                    </div>
                    <div class="content">
                        <p>Hello,</p>
                        <p>We received a request to reset your password for <strong>{email}</strong>.</p>
                        <p>Click the button below to reset your password:</p>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="{reset_link}" class="button">Reset Password</a>
                        </div>
                        <p>This link will expire in 1 hour.</p>
                        <div class="warning">
                            <strong>⚠️ Security Notice:</strong> If you didn't request this, please ignore this email. 
                            Your account security is important to us.
                        </div>
                    </div>
                    <div class="footer">
                        <p>{app_name} - Secure Authentication System</p>
                        <p>This is an automated message, please do not reply.</p>
                    </div>
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
                print(f"📧 PASSWORD RESET LINK")
                print(f"Reset Link: {reset_link}")
                print(f"{'='*60}\n")
                return True
        except Exception as e:
            print(f"❌ Failed to send reset email: {e}")
            return False
    
    # ==================== RATE LIMIT EXCEEDED HANDLER ====================
    @app.errorhandler(429)
    def ratelimit_handler(e):
        return error_response(
            "Rate limit exceeded. Please try again later.",
            429,
            {'retry_after': getattr(e, 'description', '60')}
        )
    
    # ==================== GLOBAL ERROR HANDLERS ====================
    @app.errorhandler(404)
    def not_found_error(e):
        if request.path.startswith('/api/'):
            return error_response("Endpoint not found", 404)
        return render_template('404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(e):
        db.session.rollback()
        if request.path.startswith('/api/'):
            return error_response("Internal server error", 500)
        return render_template('500.html'), 500
    
    # ==================== API ENDPOINTS ====================
    
    @app.route('/api/validate-license', methods=['POST'])
    @limiter.limit("10 per minute")
    @encrypted_request
    def validate_license():
        """Validate license and register device"""
        db_session = db.session
        try:
            data = getattr(request, '_encrypted_data', None) or request.get_json()
            
            if not data:
                return error_response("No JSON data received", 400)
            
            if not data.get('password'):
                return error_response("Password required", 400)
            
            # Sanitize inputs
            email = sanitize_input(data.get('email'), 100)
            username = sanitize_input(data.get('username'), 80)
            admission = sanitize_input(data.get('admission'), 20)
            admission_number = data.get('admission_number')
            password = sanitize_input(data.get('password'), 128)
            hwid = sanitize_input(data.get('hwid'), 256)
            
            # Find user
            identifier = email or username or admission
            if admission_number:
                identifier = str(admission_number)
            user = get_user_by_identifier(identifier)
            
            if not user:
                return error_response("Invalid credentials", 401)
            
            if not user.check_password(password):
                log_system_action(user.id, 'failed_login', 'Invalid password attempt')
                return error_response("Invalid credentials", 401)
            
            if user.is_banned:
                return error_response("Account is banned", 403, {'is_banned': True})
            
            if not user.is_license_valid():
                return error_response(
                    "License has expired. Please renew.",
                    403,
                    {
                        'license_expired': True,
                        'license_expiry': user.license_expiry_date.isoformat() if user.license_expiry_date else None
                    }
                )
            
            device_registered = False
            device_id = None
            device_name = None
            hashed_hwid = hash_hwid(hwid) if hwid else None
            session_obj = None
            
            if hashed_hwid:
                existing_device = Device.query.filter_by(
                    user_id=user.id,
                    hwid_hash=hashed_hwid
                ).first()
                
                if existing_device:
                    device_registered = True
                    device_id = existing_device.id
                    device_name = existing_device.device_name
                    
                    if not existing_device.is_active:
                        existing_device.is_active = True
                        existing_device.last_seen = datetime.utcnow()
                        existing_device.ip_address = get_real_ip()
                        db_session.add(existing_device)
                        log_device_history(user.id, 'reactivate', device_id, device_name, 'Device reactivated')
                    
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
                            user_agent=get_user_agent(),
                            expires_at=datetime.utcnow() + timedelta(hours=SESSION_DURATION_HOURS),
                            is_active=True
                        )
                        db_session.add(session_obj)
                    
                    log_device_history(user.id, 'login', device_id, device_name, 'Desktop client login')
                else:
                    # Check if bound to another account
                    other_device = Device.query.filter_by(hwid_hash=hashed_hwid, is_active=True).first()
                    if other_device:
                        return error_response(
                            "This hardware is already bound to another account",
                            403,
                            {'code': 'HWID_ALREADY_BOUND'}
                        )
                    
                    # Check device limit
                    active_count = Device.query.filter_by(user_id=user.id, is_active=True).count()
                    if active_count >= user.device_limit:
                        return error_response(
                            f'Device limit reached ({active_count}/{user.device_limit} devices)',
                            403,
                            {
                                'code': 'DEVICE_LIMIT_REACHED',
                                'requires_reset': True
                            }
                        )
                    
                    # Register new device
                    new_device = Device(
                        user_id=user.id,
                        hardware_id=hwid,
                        hwid_hash=hashed_hwid,
                        device_name=f"Desktop-{hwid[:8]}" if hwid else "Unknown-Device",
                        ip_address=get_real_ip(),
                        is_active=True,
                        is_bound=True
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
                        user_agent=get_user_agent(),
                        expires_at=datetime.utcnow() + timedelta(hours=SESSION_DURATION_HOURS),
                        is_active=True
                    )
                    db_session.add(session_obj)
                    
                    user.total_devices_registered = (user.total_devices_registered or 0) + 1
                    
                    log_device_history(user.id, 'register', device_id, device_name, 'Desktop client registered')
                    log_system_action(user.id, 'device_register', f'New device: {device_name}')
                    print(f"✅ New device registered: {device_name} for user {user.username}")
            
            if not session_obj:
                session_obj = UserSession(
                    user_id=user.id,
                    session_token=secrets.token_urlsafe(32),
                    ip_address=get_real_ip(),
                    user_agent=get_user_agent(),
                    expires_at=datetime.utcnow() + timedelta(hours=SESSION_DURATION_HOURS),
                    is_active=True
                )
                db_session.add(session_obj)
            
            db_session.commit()
            
            session_key = session_obj.session_token
            flask_session['module_key'] = session_key
            user.current_session_key = session_key
            user.last_login = datetime.utcnow()
            db_session.commit()
            
            device_count = Device.query.filter_by(user_id=user.id, is_active=True).count()
            days_remaining = get_days_remaining(user.license_expiry_date)
            
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
                'device_name': device_name
            }
            
            # Encrypt if requested
            if request.headers.get('X-Encrypt-Response', 'false').lower() == 'true':
                encrypted_response_data = encrypt_data(response_data)
                return jsonify({'encrypted': True, 'data': encrypted_response_data}), 200
            
            return jsonify(response_data), 200
            
        except Exception as e:
            db_session.rollback()
            print(f"[ERROR] Validate license: {e}")
            traceback.print_exc()
            return error_response("Internal server error", 500)
    
    @app.route('/api/get-command', methods=['POST'])
    @limiter.limit("30 per minute")
    @api_login_required
    @encrypted_request
    def get_command():
        """Fetch command definition for desktop client"""
        try:
            data = getattr(request, '_encrypted_data', None) or request.get_json()
            
            if not data:
                return error_response("No JSON data received", 400)
            
            tab = sanitize_input(data.get('tab', ''), 50).lower()
            mode = sanitize_input(data.get('mode', ''), 50).lower()
            action = sanitize_input(data.get('action', ''), 100).lower()
            device_info = data.get('device_info', {})
            
            # Validate required fields
            if not tab or not mode or not action:
                return error_response("Missing required parameters: tab, mode, action", 400)
            
            # Prevent path traversal
            if '..' in tab or '/' in tab or '\\' in tab:
                return error_response("Invalid tab parameter", 400)
            if '..' in mode or '/' in mode or '\\' in mode:
                return error_response("Invalid mode parameter", 400)
            
            print(f"🔍 Command request: tab={tab}, mode={mode}, action={action}")
            
            user = current_user
            
            # Validation
            if user.is_banned:
                return error_response("Account banned", 403, {'code': 'BANNED'})
            
            if not user.is_license_valid():
                return error_response("License expired", 403, {'code': 'LICENSE_EXPIRED'})
            
            # Map tab to folder
            tab_folders = {
                'mediatek': 'mediatek_module',
                'unisoc': 'unisoc_module',
                'xiaomi': 'xiaomi_module',
                'samsung': 'samsung_module',
                'hxd': 'hxd_module',
            }
            
            folder = tab_folders.get(tab)
            if not folder:
                return error_response(f"Unsupported tab: {tab}", 400, {
                    'supported_tabs': list(tab_folders.keys())
                })
            
            # Load commands file
            filename = f"{mode}_commands.json"
            commands_dir = os.path.join(BASE_DIR, 'commands')
            filepath = os.path.join(commands_dir, folder, filename)
            
            # Security: Ensure path is within commands directory
            if not validate_path_safety(filepath, commands_dir):
                return error_response("Invalid file path", 400)
            
            if not os.path.exists(filepath):
                return error_response(f'Commands not found for {tab}/{mode}', 404)
            
            try:
                with open(filepath, 'r') as f:
                    commands_data = json.load(f)
            except json.JSONDecodeError:
                return error_response("Invalid command configuration", 500)
            
            # Get specific action
            functions = commands_data.get('functions', {})
            function_data = functions.get(action)
            
            if not function_data:
                # Case-insensitive search
                for key, value in functions.items():
                    if key.lower() == action.lower():
                        function_data = value
                        action = key
                        break
                
                if not function_data:
                    return error_response('Action not found', 404)
            
            # Check permissions
            if function_data.get('requires_admin', False) and not user.is_admin:
                return error_response("Admin access required", 403)
            
            # Calculate cost
            cost = function_data.get('cost', get_command_cost(tab, mode, action))
            if tab == 'xiaomi' and cost == 0:
                cost = 5
                function_data['cost'] = cost
            
            # Deduct credits
            if cost > 0:
                success, message = deduct_credits(user, cost, f'Executed {tab}.{mode}.{action}')
                if not success:
                    return error_response(message, 403, {
                        'code': 'INSUFFICIENT_CREDITS',
                        'credits_needed': cost,
                        'credits_available': user.credits or 0
                    })
            
            # Log request
            device_model = device_info.get('model', 'unknown')
            device_serial = device_info.get('serial', 'unknown')
            
            log_system_action(
                user.id,
                'command_request',
                f"Command: {tab}.{mode}.{action} | Device: {device_model} ({device_serial})"
            )
            
            # Build response
            response_data = {
                'success': True,
                'tab': tab,
                'mode': mode,
                'action': action,
                'type': function_data.get('type', 'meta_action'),
                'display': function_data.get('display', ''),
                'text': function_data.get('text', ''),
                'action_command': function_data.get('action_command', ''),
                'command': function_data.get('command', ''),
                'commands': function_data.get('commands', []),
                'color': function_data.get('color', ''),
                'requires_device': function_data.get('requires_device', False),
                'device_type': function_data.get('device_type', mode),
                'cost': cost,
                'requires_admin': function_data.get('requires_admin', False),
                'timeout': function_data.get('timeout', 60),
                'chunk_size': function_data.get('chunk_size', 4194304),
                'backup_enabled': function_data.get('backup_enabled', False),
                'progress_steps': function_data.get('progress_steps', []),
                'success_message': function_data.get('success_message', '✅ Operation completed'),
                'error_message': function_data.get('error_message', '❌ Operation failed'),
                'requires_reboot': function_data.get('requires_reboot', False),
                'filter_keywords': function_data.get('filter_keywords', {}),
                'unique_filters': function_data.get('unique_filters', {}),
                'config': function_data.get('config', {}),
                'credits_remaining': user.credits or 0,
                'handshake': function_data.get('handshake', {}),
                'preloader_detection': function_data.get('preloader_detection', {}),
                'boot_methods': function_data.get('boot_methods', []),
                'meta_detection': function_data.get('meta_detection', {}),
                'final_progress': function_data.get('final_progress', 100),
                'partitions': function_data.get('partitions', []),
                'operation': function_data.get('operation', ''),
                'progress_per_partition': function_data.get('progress_per_partition', 80),
                'output_format': function_data.get('output_format', ''),
                'input_format': function_data.get('input_format', ''),
                'parse_response': function_data.get('parse_response', {}),
                'default_info': function_data.get('default_info', []),
                'requires_connection': function_data.get('requires_connection', False),
                'requires_auth': function_data.get('requires_auth', False),
                'requires_imei': function_data.get('requires_imei', False),
                'disconnect_command': function_data.get('disconnect_command', ''),
                'disconnect_delay': function_data.get('disconnect_delay', 0.5),
                'reset_connection': function_data.get('reset_connection', False),
                'requires_apk': function_data.get('requires_apk', False),
                'apk_name': function_data.get('apk_name', ''),
                'apk_download_url': function_data.get('apk_download_url', ''),
                'apk_package': function_data.get('apk_package', ''),
                'phases': function_data.get('phases', []),
                'block_apps': function_data.get('block_apps', []),
                'block_commands_per_app': function_data.get('block_commands_per_app', []),
                'global_settings': function_data.get('global_settings', []),
                'set_device_owner': function_data.get('set_device_owner', {}),
                'grant_permissions': function_data.get('grant_permissions', []),
                'launch_methods': function_data.get('launch_methods', []),
                'uninstall_apps': function_data.get('uninstall_apps', []),
                'uninstall_commands': function_data.get('uninstall_commands', []),
                'reboot': function_data.get('reboot', False),
                'sideload_commands': function_data.get('sideload_commands', []),
                'recovery_command': function_data.get('recovery_command', ''),
                'recovery_commands': function_data.get('recovery_commands', []),
                'fastboot_command': function_data.get('fastboot_command', ''),
                'fastboot_commands': function_data.get('fastboot_commands', []),
                'adb_command': function_data.get('adb_command', ''),
                'adb_commands': function_data.get('adb_commands', [])
            }
            
            print(f"✅ Command served: {tab}/{mode}/{action} (cost: {cost}, credits left: {user.credits})")
            
            # Log job
            try:
                from models import JobLog
                job_log = JobLog(
                    user_id=user.id,
                    username=user.username,
                    tab=tab,
                    mode=mode,
                    action=action,
                    device_model=device_model,
                    device_serial=device_serial,
                    cost=cost,
                    credits_remaining=user.credits or 0,
                    status='executed',
                    message=f"Command '{action}' executed",
                    ip_address=get_real_ip(),
                    user_agent=get_user_agent()
                )
                db.session.add(job_log)
                db.session.commit()
            except:
                pass  # Ignore logging errors
            
            # Encrypt if requested
            if request.headers.get('X-Encrypt-Response', 'false').lower() == 'true':
                encrypted_response_data = encrypt_data(response_data)
                return jsonify({'encrypted': True, 'data': encrypted_response_data}), 200
            
            return jsonify(response_data), 200
            
        except Exception as e:
            db.session.rollback()
            print(f"❌ Command error: {e}")
            traceback.print_exc()
            return error_response("An error occurred while processing your request", 500)
    
    # ==================== USER API ENDPOINTS ====================
    
    @app.route('/api/user/info')
    @api_login_required
    @encrypted_response
    def user_info():
        """Get user information"""
        try:
            user = current_user
            return success_response({
                'username': user.username,
                'email': user.email,
                'credits': user.credits or 0,
                'admission_number': user.admission_number,
                'country': user.country or 'Not set',
                'is_banned': user.is_banned,
                'is_active': user.is_active,
                'created_at': user.created_at.isoformat() if user.created_at else None
            })
        except Exception as e:
            return error_response(str(e), 500)
    
    @app.route('/api/user/profile')
    @api_login_required
    @encrypted_response
    def user_profile():
        """Get user profile"""
        try:
            user = current_user
            days_remaining = get_days_remaining(user.license_expiry_date)
            device_count = Device.query.filter_by(user_id=user.id, is_active=True).count()
            device_limit_display = 'Unlimited' if user.device_limit >= 999999 else user.device_limit
            
            return success_response({
                'username': user.username,
                'email': user.email,
                'credits': user.credits or 0,
                'admission_number': user.admission_number,
                'country': user.country or 'Not specified',
                'is_banned': user.is_banned,
                'is_active': user.is_active,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'commission_rate': user.commission_rate or 0,
                'total_commission': user.total_commission or 0,
                'license_type': user.license_type or 'None',
                'license_status': 'Active' if user.is_license_valid() else 'Expired',
                'license_expiry': user.license_expiry_date.isoformat() if user.license_expiry_date else None,
                'days_remaining': days_remaining,
                'device_limit': device_limit_display,
                'device_count': device_count,
                'license_key': getattr(user, 'license_key', 'N/A')
            })
        except Exception as e:
            return error_response(str(e), 500)
    
    @app.route('/api/user/devices')
    @api_login_required
    @encrypted_response
    def user_devices():
        """Get user devices"""
        try:
            devices = Device.query.filter_by(user_id=current_user.id).order_by(Device.created_at.desc()).all()
            
            devices_data = []
            for d in devices:
                devices_data.append({
                    'id': d.id,
                    'device_name': d.device_name or 'Unknown Device',
                    'hwid': d.hwid_hash[:16] + '...' if d.hwid_hash else 'N/A',
                    'is_active': d.is_active,
                    'is_trusted': getattr(d, 'is_trusted', False),
                    'created_at': d.created_at.isoformat() if d.created_at else None,
                    'last_seen': d.last_seen.isoformat() if d.last_seen else None,
                    'ip_address': d.ip_address
                })
            
            return success_response({
                'devices': devices_data,
                'total': len(devices_data),
                'device_limit': current_user.device_limit
            })
        except Exception as e:
            return error_response(str(e), 500)
    
    @app.route('/api/user/reset-devices', methods=['POST'])
    @limiter.limit("5 per hour")
    @api_login_required
    @encrypted_request
    def user_reset_devices():
        """Reset one or all devices"""
        try:
            data = getattr(request, '_encrypted_data', None) or request.get_json() or {}
            device_id = data.get('device_id')
            
            user = current_user
            reset_cost = DEVICE_RESET_COST
            
            if not device_id:
                # Reset all devices
                devices = Device.query.filter_by(user_id=user.id, is_active=True).all()
                
                if not devices:
                    return error_response("No active devices to reset", 400)
                
                total_cost = reset_cost * len(devices)
                
                if (user.credits or 0) < total_cost:
                    return error_response(f'Insufficient credits. Need {total_cost} credits', 400)
                
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
                
                return success_response({'message': f'Successfully reset {len(devices)} devices'})
            
            else:
                # Reset single device
                device = Device.query.filter_by(id=device_id, user_id=user.id).first()
                
                if not device:
                    return error_response("Device not found", 404)
                
                if (user.credits or 0) < reset_cost:
                    return error_response(f'Insufficient credits. Need {reset_cost} credits', 400)
                
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
                
                return success_response({'message': f'Device "{device.device_name}" reset successfully'})
                
        except Exception as e:
            db.session.rollback()
            print(f"Error in user_reset_devices: {e}")
            return error_response(str(e), 500)
    
    @app.route('/api/user/stats')
    @api_login_required
    @encrypted_response
    def user_stats():
        """Get user statistics"""
        try:
            user = current_user
            devices = Device.query.filter_by(user_id=user.id, is_active=True).all()
            total_devices = len(devices)
            device_limit = user.device_limit if user.device_limit < 999999 else 999999
            remaining = device_limit - total_devices if user.device_limit < 999999 else 'Unlimited'
            
            return success_response({
                'total_devices': total_devices,
                'device_limit': device_limit,
                'remaining_slots': remaining,
                'credits': user.credits or 0
            })
        except Exception as e:
            return error_response(str(e), 500)
    
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
    @limiter.limit("5 per minute")
    def login():
        if current_user.is_authenticated:
            if current_user.is_admin:
                return redirect('/admin-dashboard')
            elif current_user.is_reseller:
                return redirect('/reseller-dashboard')
            return redirect('/user-dashboard')
        
        if request.method == 'POST':
            try:
                email = sanitize_input(request.form.get('email'), 100)
                admission = sanitize_input(request.form.get('admission'), 20)
                password = sanitize_input(request.form.get('password'), 128)
                
                user = get_user_by_identifier(email or admission)
                
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
    @limiter.limit("3 per hour")
    def register():
        if current_user.is_authenticated:
            return redirect('/user-dashboard')
        
        if request.method == 'POST':
            try:
                username = sanitize_input(request.form.get('username'), 80)
                email = sanitize_input(request.form.get('email'), 100).lower()
                country = sanitize_input(request.form.get('country'), 50)
                password = sanitize_input(request.form.get('password'), 128)
                confirm = sanitize_input(request.form.get('confirm_password'), 128)
                
                errors = []
                if User.query.filter_by(username=username).first():
                    errors.append("Username already exists")
                if User.query.filter_by(email=email).first():
                    errors.append("Email already registered")
                if password != confirm:
                    errors.append("Passwords do not match")
                
                valid, msg = validate_password_strength(password)
                if not valid:
                    errors.append(msg)
                
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
    @limiter.limit("3 per hour")
    def forgot_password():
        if current_user.is_authenticated:
            return redirect('/user-dashboard')
        
        if request.method == 'POST':
            email = sanitize_input(request.form.get('email'), 100)
            user = User.query.filter_by(email=email).first()
            
            if user:
                reset_token = user.generate_reset_token()
                db.session.commit()
                send_reset_email(email, reset_token)
                flash('Password reset link has been sent to your email.', 'success')
                log_system_action(user.id, 'password_reset_request', f'Password reset requested')
            else:
                flash('If an account exists with that email, a reset link has been sent.', 'info')
            
            return redirect(url_for('login'))
        
        return render_template('forgot_password.html')
    
    @app.route('/reset-password/<token>', methods=['GET', 'POST'])
    def reset_password(token):
        if current_user.is_authenticated:
            return redirect('/user-dashboard')
        
        user = User.query.filter_by(reset_token=token).first()
        
        if not user or not user.verify_reset_token(token):
            flash('Invalid or expired reset token.', 'danger')
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            password = sanitize_input(request.form.get('password'), 128)
            confirm = sanitize_input(request.form.get('confirm_password'), 128)
            
            if password != confirm:
                flash('Passwords do not match.', 'danger')
                return render_template('reset_password.html', token=token)
            
            valid, msg = validate_password_strength(password)
            if not valid:
                flash(msg, 'danger')
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
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '2.0.0'
        })
    
    # ==================== VERSION CHECK ====================
    @app.route('/api/check-version', methods=['GET'])
    def check_version():
        """Check for latest desktop client version"""
        try:
            current_version = request.args.get('version', '0')
            version_file = os.path.join(BASE_DIR, 'version.json')
            
            if os.path.exists(version_file):
                with open(version_file, 'r') as f:
                    version_data = json.load(f)
            else:
                version_data = {
                    'latest_version': '1.1.0',
                    'download_url': 'https://my-dolphin-tool-2.onrender.com/download',
                    'changelog': 'Initial release',
                    'force_update': False,
                    'release_date': datetime.now().isoformat()
                }
            
            needs_update = version_data['latest_version'] != current_version
            
            response_data = {
                'success': True,
                'needs_update': needs_update,
                'latest_version': version_data['latest_version'],
                'current_version': current_version,
                'download_url': version_data['download_url'],
                'changelog': version_data.get('changelog', ''),
                'force_update': version_data.get('force_update', False)
            }
            
            if request.headers.get('X-Encrypt-Response', 'false').lower() == 'true':
                encrypted_response_data = encrypt_data(response_data)
                return jsonify({'encrypted': True, 'data': encrypted_response_data}), 200
            
            return jsonify(response_data), 200
            
        except Exception as e:
            print(f"Error in check_version: {e}")
            return error_response(str(e), 500)
    
    # ==================== SERVE APK FILE ====================
    @app.route('/AT-TOOL-GUARD.apk')
    def download_apk():
        apk_path = os.path.join(BASE_DIR, 'AT-TOOL-GUARD.apk')
        if os.path.exists(apk_path):
            return send_file(apk_path, mimetype='application/vnd.android.package-archive', as_attachment=True)
        else:
            return error_response("APK not found", 404)
    
    # ==================== ADMIN ENDPOINTS ====================
    
    @app.route('/api/admin/sync-commands', methods=['POST'])
    @login_required
    @admin_required
    def sync_commands():
        """Admin only: Sync commands from GitHub"""
        import subprocess
        import shutil
        
        commands_dir = os.path.join(BASE_DIR, 'commands')
        git_repo = "https://github.com/clintonmoipan34-stack/My-mdm-Tool.git"
        
        try:
            backup_dir = f"{commands_dir}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            if os.path.exists(commands_dir):
                shutil.copytree(commands_dir, backup_dir)
                print(f"📦 Backup created: {backup_dir}")
            
            if os.path.exists(commands_dir):
                result = subprocess.run(['git', '-C', commands_dir, 'pull'],
                                       capture_output=True, text=True, timeout=60)
                message = result.stdout or result.stderr
            else:
                result = subprocess.run(['git', 'clone', git_repo, commands_dir],
                                       capture_output=True, text=True, timeout=120)
                message = result.stdout or result.stderr
            
            validated_count = 0
            error_count = 0
            
            for root, dirs, files in os.walk(commands_dir):
                for file in files:
                    if file.endswith('.json'):
                        filepath = os.path.join(root, file)
                        try:
                            with open(filepath, 'r') as f:
                                json.load(f)
                            validated_count += 1
                        except:
                            error_count += 1
            
            log_system_action(current_user.id, 'sync_commands', f'Commands synced. Validated: {validated_count}')
            
            return success_response({
                'message': f'Commands synced successfully. Validated {validated_count} JSON files.',
                'details': message,
                'validated': validated_count,
                'errors': error_count
            })
            
        except subprocess.TimeoutExpired:
            return error_response("Git operation timed out", 500)
        except Exception as e:
            return error_response(str(e), 500)
    
    return app

# ==================== CREATE APP INSTANCE ====================
app = create_app()

# ==================== MAIN ====================
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    print("\n" + "="*60)
    print(f"🚀 Server running on port {port}")
    print(f"🔧 Debug mode: {debug}")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=port, debug=debug)