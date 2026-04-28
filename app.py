from flask import send_from_directory
import os  # Make sure this is at the top
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

# ==================== CONSTANTS ====================
SESSION_DURATION_HOURS = 12       # Hardware binding: 12 hours
SESSION_INACTIVITY_MINUTES = 30   # Inactivity timeout: 30 minutes
DEVICE_RESET_COST = 2

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
    
    with app.app_context():
        db.create_all()
        print("✅ Database tables created/verified")
        
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

            
            reset_link = f"{base_url}/auth/reset-password/{reset_token}"
            
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
                db.session.commit()
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
                        user_agent=request.headers.get('User-Agent')[:500] if request.headers.get('User-Agent') else None,
                        expires_at=datetime.utcnow() + timedelta(hours=SESSION_DURATION_HOURS),
                        is_active=True
                    )
                    db_session.add(session_obj)
                    
                    user.total_devices_registered = (user.total_devices_registered or 0) + 1
                    
                    log_device_history(user.id, 'register', device_id, device_name, 'Desktop client registered')
                    log_system_action(user.id, 'device_register', f'New desktop client registered: {device_name}')
                    print(f"✅ New device registered: {device_name} for user {user.username}")
            
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

            # Update last login (ONLY ONCE)
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
            
            if hwid:
                hashed_hwid = hash_hwid(hwid)
                device = db.session.get(Device, session_obj.device_id)
                if not device or device.hwid_hash != hashed_hwid:
                    return jsonify({'success': False, 'valid': False, 'error': 'Session does not match device'}), 403
            
            # Update last activity timestamp
            session_obj.last_activity = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'success': True,
                'valid': True,
                'user_id': session_obj.user_id,
                'expires_at': session_obj.expires_at.isoformat(),
                'device_id': session_obj.device_id
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500


            
    
    # ==================== USER DASHBOARD API ENDPOINTS ====================
    # Using api_login_required instead of login_required for API endpoints
    
    @app.route('/api/user/info')
    @api_login_required
    def user_info():
        try:
            user = current_user
            if not user:
                return jsonify({'success': False, 'error': 'User not authenticated'}), 401
            return jsonify({
                'success': True,
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
            
            return jsonify({
                'success': True,
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
                'device_limit': user.device_limit if user.device_limit < 999999 else 'Unlimited',
                'device_count': device_count,
                'license_key': getattr(user, 'license_key', 'N/A')
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
                    'is_active': d.is_active,
                    'is_trusted': getattr(d, 'is_trusted', False),
                    'created_at': d.created_at.isoformat() if d.created_at else None,
                    'last_seen': d.last_seen.isoformat() if d.last_seen else None,
                    'ip_address': d.ip_address
                })
            
            return jsonify({
                'success': True,
                'devices': devices_data,
                'total': len(devices_data),
                'device_limit': current_user.device_limit
            })
        except Exception as e:
            print(f"Error in user_devices: {e}")
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
        """Get device history/logs"""
        try:
            history = DeviceHistory.query.filter_by(user_id=current_user.id).order_by(DeviceHistory.created_at.desc()).limit(50).all()
            
            history_list = []
            for h in history:
                history_list.append({
                    'action': h.action,
                    'reason': h.reason,
                    'device_name': h.device_name,
                    'created_at': h.created_at.isoformat() if h.created_at else None,
                    'ip_address': h.ip_address
                })
            
            if not history_list:
                logs = SystemLog.query.filter_by(user_id=current_user.id).order_by(SystemLog.created_at.desc()).limit(50).all()
                for log in logs:
                    history_list.append({
                        'action': log.log_type,
                        'reason': log.message,
                        'device_name': None,
                        'created_at': log.created_at.isoformat() if log.created_at else None,
                        'ip_address': log.ip_address
                    })
            
            return jsonify({
                'success': True,
                'history': history_list,
                'total': len(history_list)
            })
        except Exception as e:
            print(f"Error in user_device_history: {e}")
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
    # ADD THESE THREE ENDPOINTS:

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
                'this_month_earnings': this_month_earnings,
                'total_clients': total_clients,
                'active_clients': active_clients,
                'expired_clients': expired_clients,
                'this_month_clients': this_month_clients,
                'pending_requests': pending_requests
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
        """Activate license directly - no admin approval needed"""
        try:
            user = current_user
            if not user.is_reseller and not user.is_admin:
                return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            
            # Check activation limit
            if user.is_reseller:
                used = user.activations_used or 0
                limit = user.activation_limit or 10
                if used >= limit:
                    return jsonify({
                        'success': False, 
                        'error': f'Activation limit reached ({used}/{limit})'
                    }), 403
            
            data = request.get_json()
            full_name = data.get('full_name', '').strip()
            email = data.get('email', '').strip().lower()
            country = data.get('country', '')
            license_type = data.get('license_type', '12hr')
            
            if not full_name or not email:
                return jsonify({'success': False, 'error': 'Missing fields'}), 400
            
            if User.query.filter_by(email=email).first():
                return jsonify({'success': False, 'error': 'Email exists'}), 400
            
            # Generate username
            username = full_name.lower().replace(' ', '.')
            base = username
            counter = 1
            while User.query.filter_by(username=username).first():
                username = f"{base}{counter}"; counter += 1
            
            admission_number = get_next_admission_number()
            
      # ✅ Reseller durations and device limits (fixed by admin)
            durations = {
                '12hr': 1,
                '3_months': 90,
                '6_months': 180,
                '1_year': 365
            }
            device_limits = {
                '12hr': 1,       # 12 hours = 1 device
                '3_months': 10,  # 3 months = 10 devices
                '6_months': 20,  # 6 months = 20 devices
                '1_year': 45     # 12 months = 45 devices
            }
            days = durations.get(license_type, 90)
            device_limit = device_limits.get(license_type, 1)
            
            import random
            import string
            temp_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            
            new_user = User(
                username=username, email=email, country=country,
                admission_number=admission_number, credits=0,
                device_limit=device_limit,
                license_type=license_type,
                license_expiry_date=datetime.utcnow() + timedelta(days=days),
                license_status='active', license_valid=True,
                activated_by=current_user.id
            )
            new_user.set_password(temp_password)
            db.session.add(new_user)
            
            # Increment activation count
            if current_user.is_reseller:
                current_user.activations_used = (current_user.activations_used or 0) + 1
            
            db.session.commit()
            
            log_system_action(current_user.id, 'reseller_activate', 
                            f'Activated {license_type} ({days}d) for {email}')
            
            return jsonify({
                'success': True,
                'message': f'License activated for {email}',
                'temp_password': temp_password,
                'client': {
                    'username': username, 'email': email,
                    'license_type': license_type, 'days': days
                }
            })
        except Exception as e:
            db.session.rollback()
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
        Expects: {"tab": "mediatek", "mode": "mdm", "action": "read_info", "device_info": {}}
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
            
            # DEBUG: Print what we're looking for
            print(f"🔍 [DEBUG] Looking for: tab={tab}, mode={mode}, action={action}")
            
            user = current_user
            
            # 1. VALIDATION
            if user.is_banned:
                return jsonify({'error': 'Account banned', 'code': 'BANNED'}), 403
            
            if not user.is_license_valid():
                return jsonify({'error': 'License expired/not activated', 'code': 'LICENSE_EXPIRED'}), 403
            
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
                # APK Download Information
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
    #  OTP MANAGEMENT API
    # ═══════════════════════════════════════════════════════════
    
    OTP_TYPES = {
        'oppo_flash': {'name': 'OPPO Flash OTP', 'cost': 20},
        'tecno_anticrack': {'name': 'Tecno/Itel/Infinix AntiCrack', 'cost': 10},
        'tecno_anticrack_p7': {'name': 'Tecno/Itel/Infinix AntiCrack P7', 'cost': 12},
        'tecno_auth_mtk': {'name': 'Tecno/Itel/Infinix Auth Flash MTK', 'cost': 9},
        'infinix_auth_mtk': {'name': 'Infinix Auth Flash MTK', 'cost': 8},
        'tecno_auth_spd': {'name': 'Tecno/Itel/Infinix Auth Flash SPD', 'cost': 13},
        'tecno_cpid': {'name': 'Tecno/Itel/Infinix CPID', 'cost': 20},
        'realme_mtk': {'name': 'Realme MTK OTP', 'cost': 5},
        'oneplus': {'name': 'OnePlus OTP', 'cost': 6},
    }

    from database import StoredOTP

    # ── ADMIN: Add OTPs ──
    @app.route('/api/admin/otps/add', methods=['POST'])
    @login_required
    def admin_add_otps():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        data = request.get_json()
        otp_type = data.get('otp_type', '').strip().lower()
        otp_codes = data.get('otp_codes', [])
        notes = data.get('notes', '').strip()
        if otp_type not in OTP_TYPES:
            return jsonify({'error': f'Invalid OTP type. Valid: {", ".join(OTP_TYPES.keys())}'}), 400
        if not otp_codes or not isinstance(otp_codes, list):
            return jsonify({'error': 'otp_codes must be a non-empty list'}), 400
        otp_info = OTP_TYPES[otp_type]
        added, duplicates, skipped = 0, 0, 0
        for code in otp_codes:
            code = str(code).strip()
            if not code: skipped += 1; continue
            if StoredOTP.query.filter_by(otp_code=code).first(): duplicates += 1; continue
            otp = StoredOTP(otp_code=code, otp_type=otp_type, otp_name=otp_info['name'],
                           credits_cost=otp_info['cost'], notes=notes, created_by=current_user.id)
            db.session.add(otp); added += 1
        db.session.commit()
        log_system_action(current_user.id, 'otp_add', f'Added {added} {otp_info["name"]} OTPs')
        return jsonify({'success': True, 'message': f'Added {added} OTPs', 'stats': {'added': added, 'duplicates': duplicates, 'skipped': skipped}})

    # ── ADMIN: OTP Stats ──
    @app.route('/api/admin/otps/stats', methods=['GET'])
    @login_required
    def admin_otp_stats():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        stats = {}
        for otp_type, info in OTP_TYPES.items():
            total = StoredOTP.query.filter_by(otp_type=otp_type).count()
            available = StoredOTP.query.filter_by(otp_type=otp_type, is_used=False).count()
            used = StoredOTP.query.filter_by(otp_type=otp_type, is_used=True).count()
            recent = StoredOTP.query.filter_by(otp_type=otp_type, is_used=True).order_by(StoredOTP.used_at.desc()).limit(5).all()
            stats[otp_type] = {'name': info['name'], 'cost': info['cost'], 'total': total, 'available': available, 'used': used,
                              'recent_usage': [{'id': o.id, 'used_by': o.user.username if o.user else '?', 'used_at': o.used_at.isoformat() if o.used_at else None} for o in recent]}
        return jsonify({'success': True, 'stats': stats, 'summary': {'total_available': sum(s['available'] for s in stats.values()), 'total_used': sum(s['used'] for s in stats.values())}})

    # ── ADMIN: List OTPs ──
    @app.route('/api/admin/otps/list', methods=['GET'])
    @login_required
    def admin_otp_list():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        otp_type = request.args.get('type', '').strip()
        status = request.args.get('status', 'all')
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 50))
        query = StoredOTP.query
        if otp_type and otp_type in OTP_TYPES: query = query.filter_by(otp_type=otp_type)
        if status == 'available': query = query.filter_by(is_used=False)
        elif status == 'used': query = query.filter_by(is_used=True)
        query = query.order_by(StoredOTP.created_at.desc())
        total = query.count()
        otps = query.offset((page-1)*limit).limit(limit).all()
        return jsonify({'success': True, 'otps': [o.to_dict(admin_view=True) for o in otps], 'total': total, 'page': page, 'limit': limit})

    # ── ADMIN: Used History ──
    @app.route('/api/admin/otps/used-history', methods=['GET'])
    @login_required
    def admin_otp_used_history():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 50))
        query = StoredOTP.query.filter_by(is_used=True).order_by(StoredOTP.used_at.desc())
        total = query.count()
        otps = query.offset((page-1)*limit).limit(limit).all()
        history = [{'id': o.id, 'otp_type': o.otp_type, 'otp_name': o.otp_name, 'cost': o.credits_cost,
                    'used_by': o.user.username if o.user else '?', 'used_by_email': o.user.email if o.user else '?',
                    'used_at': o.used_at.isoformat() if o.used_at else None} for o in otps]
        return jsonify({'success': True, 'history': history, 'total': total})

    # ── ADMIN: Delete OTP ──
    @app.route('/api/admin/otps/delete/<int:otp_id>', methods=['DELETE'])
    @login_required
    def admin_delete_otp(otp_id):
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        otp = StoredOTP.query.get(otp_id)
        if not otp: return jsonify({'error': 'OTP not found'}), 404
        if otp.is_used: return jsonify({'error': 'Cannot delete used OTP'}), 400
        db.session.delete(otp); db.session.commit()
        return jsonify({'success': True, 'message': 'OTP deleted'})

    # ── USER: Request OTP (FULL SECURITY + ATOMIC) ──
    @app.route('/api/user/otps/request', methods=['POST'])
    @api_login_required
    def user_request_otp():
        db_session = db.session
        user = current_user
        
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
        if not data: return jsonify({'success': False, 'error': 'No JSON data'}), 400
        otp_type = data.get('otp_type', '').strip().lower()
        if not otp_type or otp_type not in OTP_TYPES:
            return jsonify({'success': False, 'error': f'Invalid OTP type', 'valid_types': list(OTP_TYPES.keys())}), 400
        
        otp_info = OTP_TYPES[otp_type]
        cost = otp_info['cost']
        otp_name = otp_info['name']
        user_credits = user.credits or 0
        
        if user_credits < cost:
            return jsonify({'success': False, 'error': f'Need {cost} credits. You have {user_credits}', 'code': 'INSUFFICIENT_CREDITS', 'credits_needed': cost, 'credits_available': user_credits}), 403
        
        otp = StoredOTP.query.filter_by(otp_type=otp_type, is_used=False).order_by(StoredOTP.id).first()
        if not otp:
            return jsonify({'success': False, 'error': f'No {otp_name} OTPs available', 'code': 'OTP_OUT_OF_STOCK'}), 404
        
        try:
            user.credits = user_credits - cost
            otp.is_used = True; otp.used_by = user.id; otp.used_at = datetime.utcnow()
            transaction = CreditTransaction(user_id=user.id, amount=-cost, transaction_type='otp_purchase',
                                           description=f'Purchased {otp_name} OTP (ID: {otp.id})')
            db_session.add(transaction)
            new_count = increment_command_count(user.id)
            log_system_action(user.id, 'otp_purchase', f'Purchased {otp_name} OTP for {cost} credits. Remaining: {user.credits}')
            db_session.commit()
            otp_code = otp.otp_code
            return jsonify({'success': True, 'otp_code': otp_code, 'otp_type': otp_type, 'otp_name': otp_name,
                           'cost': cost, 'credits_remaining': user.credits, 'commands_used_today': new_count,
                           'usage_note': '⚠️ Save this code now! It will NOT be shown again.'}), 200
        except Exception as e:
            db_session.rollback()
            print(f"❌ OTP purchase failed: {e}")
            return jsonify({'success': False, 'error': 'Transaction failed. No credits deducted.', 'code': 'TRANSACTION_FAILED'}), 500

    # ── USER: OTP History ──
    @app.route('/api/user/otps/history', methods=['GET'])
    @api_login_required
    def user_otp_history():
        purchases = StoredOTP.query.filter_by(used_by=current_user.id).order_by(StoredOTP.used_at.desc()).limit(50).all()
        history = [{'id': p.id, 'type': p.otp_type, 'name': p.otp_name, 'cost': p.credits_cost, 'used_at': p.used_at.isoformat() if p.used_at else None} for p in purchases]
        return jsonify({'success': True, 'history': history, 'total': len(history), 'total_spent': sum(p.credits_cost for p in purchases)})


    return app

app = create_app()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
