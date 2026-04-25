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

# ==================== CONSTANTS ====================
SESSION_DURATION_HOURS = 2
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
    
    db.init_app(app)
    
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
                    credits=1000,
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
    
    def set_maintenance(enabled, msg="Under maintenance"):
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
                return jsonify({'success': False, 'error': 'Maintenance in progress', 'maintenance': True}), 503
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
            base_url = config.get('BASE_URL', 'http://localhost:5000')
            
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
    
    # ==================== API ENDPOINTS FOR DESKTOP CLIENT ====================
    
    @app.route('/api/validate-license', methods=['POST'])
    def validate_license():
        db_session = db.session
        try:
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
                return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
            
            if not user.check_password(password):
                return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
            
            if user.is_banned:
                return jsonify({'success': False, 'error': 'Account is banned', 'is_banned': True}), 403
            
            if not user.is_license_valid():
                return jsonify({
                    'success': False, 
                    'error': 'License has expired. Please renew your license.',
                    'license_expired': True,
                    'license_expiry': user.license_expiry_date.isoformat() if user.license_expiry_date else None
                }), 403
            
            device_registered = False
            device_id = None
            device_name = None
            hashed_hwid = hash_hwid(hwid) if hwid else None
            session_obj = None
            
            if hashed_hwid:
                # Check for existing device (active OR inactive)
                existing_device = Device.query.filter_by(
                    user_id=user.id,
                    hwid_hash=hashed_hwid
                ).first()
                
                if existing_device:
                    # Device exists - reactivate it if needed
                    device_registered = True
                    device_id = existing_device.id
                    device_name = existing_device.device_name
                    
                    # Reactivate if inactive
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
                        # Create new session for existing device
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
                    # Check if device is bound to another account
                    other_device = Device.query.filter_by(hwid_hash=hashed_hwid, is_active=True).first()
                    if other_device:
                        return jsonify({
                            'success': False, 
                            'error': 'This hardware is already bound to another account',
                            'code': 'HWID_ALREADY_BOUND'
                        }), 403
                    
                    active_count = Device.query.filter_by(user_id=user.id, is_active=True).count()
                    if active_count >= user.device_limit:
                        return jsonify({
                            'success': False,
                            'error': f'Device limit reached ({active_count}/{user.device_limit} devices)',
                            'code': 'DEVICE_LIMIT_REACHED',
                            'requires_reset': True
                        }), 403
                    
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
                # Create a session without device if no device was registered
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
            
            device_count = Device.query.filter_by(user_id=user.id, is_active=True).count()
            
            days_remaining = 0
            if user.license_expiry_date:
                days_remaining = (user.license_expiry_date - datetime.utcnow()).days
                if days_remaining < 0:
                    days_remaining = 0
            
            return jsonify({
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
            }), 200
            
        except Exception as e:
            db_session.rollback()
            print(f"[ERROR] Validate license error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/user/validate-session', methods=['POST'])
    def validate_session_endpoint():
        try:
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
            
            if hwid:
                hashed_hwid = hash_hwid(hwid)
                device = db.session.get(Device, session_obj.device_id)
                if not device or device.hwid_hash != hashed_hwid:
                    return jsonify({'success': False, 'valid': False, 'error': 'Session does not match device'}), 403
            
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
            return redirect('/user-dashboard')
        
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
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.is_reseller = True
        user.commission_rate = commission_rate
        db.session.commit()
        
        log_system_action(current_user.id, 'reseller', f'Made {user.username} a reseller with {commission_rate}% commission')
        
        return jsonify({'success': True})
    
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
    
    @app.route('/api/reseller/pending-requests')
    @api_login_required
    def reseller_pending_requests():
        """Get pending approval requests"""
        try:
            user = current_user
            if not user.is_reseller and not user.is_admin:
                return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            
            pending = User.query.filter_by(activated_by=user.id, license_status='pending').order_by(User.created_at.desc()).all()
            
            pending_data = [{
                'id': p.id,
                'client_name': p.username,
                'client_email': p.email,
                'license_type': p.license_type,
                'amount': 0,
                'created_at': p.created_at.isoformat() if p.created_at else None
            } for p in pending]
            
            return jsonify({
                'success': True,
                'requests': pending_data,
                'total': len(pending_data)
            })
        except Exception as e:
            print(f"Error in reseller_pending_requests: {e}")
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
    
    @app.route('/api/reseller/activate', methods=['POST'])
    @api_login_required
    def reseller_activate_license():
        """Activate license for a new client (reseller) - creates pending request"""
        try:
            data = request.get_json()
            
            full_name = data.get('full_name', '').strip()
            email = data.get('email', '').strip().lower()
            country = data.get('country', '')
            phone = data.get('phone', '')
            license_type = data.get('license_type')
            payment_method = data.get('payment_method')
            payment_reference = data.get('payment_reference', '')
            
            # Validation
            if not full_name or not email or not license_type:
                return jsonify({'success': False, 'error': 'Missing required fields'}), 400
            
            # Check if user already exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                return jsonify({'success': False, 'error': 'User with this email already exists'}), 400
            
            # Generate username from full name
            username = full_name.lower().replace(' ', '.')
            base_username = username
            counter = 1
            while User.query.filter_by(username=username).first():
                username = f"{base_username}{counter}"
                counter += 1
            
            # Get admission number
            admission_number = get_next_admission_number()
            
            # Create new user with pending status
            new_user = User(
                username=username,
                email=email,
                country=country,
                admission_number=admission_number,
                credits=0,
                device_limit=1,
                license_type=license_type,
                license_status='pending',
                license_valid=False,
                activated_by=current_user.id,
                phone=phone
            )
            
            # Generate random password
            import random
            import string
            temp_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            new_user.set_password(temp_password)
            
            db.session.add(new_user)
            db.session.commit()
            
            log_system_action(current_user.id, 'reseller_activate', f'Created pending activation for {email}')
            
            return jsonify({
                'success': True,
                'message': f'Activation request submitted for {email}. Waiting for admin approval.',
                'temp_password': temp_password,
                'client': {
                    'username': username,
                    'email': email,
                    'admission_number': admission_number,
                    'license_type': license_type
                }
            })
        except Exception as e:
            db.session.rollback()
            print(f"Error in reseller_activate_license: {e}")
            traceback.print_exc()
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
    
    @app.route('/api/admin/make-reseller/<int:user_id>', methods=['POST'])
    @login_required
    def admin_make_reseller_api(user_id):
        """Make a user a reseller"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        commission_rate = data.get('commission_rate', 15)
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.is_reseller = True
        user.commission_rate = commission_rate
        
        db.session.commit()
        
        log_system_action(current_user.id, 'make_reseller', f'Made {user.username} a reseller with {commission_rate}% commission')
        
        return jsonify({'success': True, 'message': f'{user.username} is now a reseller'})
    
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
    
    @app.route('/api/admin/approve-reseller-request/<int:user_id>', methods=['POST'])
    @login_required
    def admin_approve_reseller_request(user_id):
        """Approve a reseller request"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        commission_rate = data.get('commission_rate', 15)
        
        user.is_reseller = True
        user.commission_rate = commission_rate
        
        db.session.commit()
        
        log_system_action(current_user.id, 'approve_reseller', f'Approved reseller request for {user.username}')
        
        return jsonify({'success': True, 'message': f'Reseller request approved for {user.username}'})
    
    @app.route('/api/admin/approve-pending-license/<int:user_id>', methods=['POST'])
    @login_required
    def admin_approve_pending_license(user_id):
        """Approve a pending license activation from reseller"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        license_type = data.get('license_type')
        duration_days = data.get('duration_days', 30)
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Calculate expiry date based on license type
        durations = {
            '24_hours': 1,
            '2_days': 2,
            '1_week': 7,
            '1_month': 30,
            '3_months': 90,
            '6_months': 180,
            '1_year': 365
        }
        
        days = durations.get(license_type, duration_days)
        
        user.license_type = license_type
        user.license_expiry_date = datetime.utcnow() + timedelta(days=days)
        user.license_status = 'active'
        user.license_valid = True
        user.device_limit = 1  # 1 PC limit for reseller clients
        
        db.session.commit()
        
        # Add commission to reseller
        if user.activated_by:
            reseller = User.query.get(user.activated_by)
            if reseller:
                # Calculate commission (example: 15% of 500 = 75)
                price_map = {
                    '24_hours': 300,
                    '2_days': 500,
                    '1_week': 1000,
                    '1_month': 1500,
                    '3_months': 3500,
                    '6_months': 3000,
                    '1_year': 5000
                }
                price = price_map.get(license_type, 500)
                commission = (price * (reseller.commission_rate or 15)) // 100
                
                reseller.credits = (reseller.credits or 0) + commission
                reseller.total_commission = (reseller.total_commission or 0) + commission
                reseller.total_sales = (reseller.total_sales or 0) + price
                
                # Record transaction
                transaction = CreditTransaction(
                    user_id=user.id,
                    amount=price,
                    transaction_type='reseller_sale',
                    description=f'License activation: {license_type} by reseller {reseller.username}',
                    created_by=reseller.id
                )
                db.session.add(transaction)
                db.session.commit()
        
        log_system_action(current_user.id, 'approve_license', f'Approved license for {user.username}')
        
        return jsonify({'success': True, 'message': f'License approved for {user.username}'})
    
    @app.route('/api/admin/deny-pending-license/<int:user_id>', methods=['DELETE', 'POST'])
    @login_required
    def admin_deny_pending_license(user_id):
        """Deny a pending license activation and delete the user"""
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Delete the user (cascade will handle related records)
        db.session.delete(user)
        db.session.commit()
        
        log_system_action(current_user.id, 'deny_license', f'Denied and deleted pending user {user.email}')
        
        return jsonify({'success': True, 'message': 'License request denied and user deleted'})

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

        #commands 
            #commands ################################# 
    # ==================== COMMAND FETCH ENDPOINT ====================
    @app.route('/api/get-command', methods=['POST'])
    @api_login_required
    def get_command():
        """
        Fetch command definition for desktop client
        Expects: {"tab": "mediatek", "mode": "mdm", "action": "read_info", "device_info": {}}
        """
        try:
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
                return jsonify({'error': 'License expired/not activated', 'code': 'LICENSE_EXPIRED/NOT ACTIVATED'}), 403
            
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
            
            # 3. MAP MODE to JSON file (with _commands suffix)
            filename = f"{mode}_commands.json"
            
            # 4. LOAD COMMANDS FROM SERVER
            commands_dir = os.path.join(BASE_DIR, 'commands')
            filepath = os.path.join(commands_dir, folder, filename)
            
            # DEBUG: Print paths
            print(f"📁 [DEBUG] BASE_DIR: {BASE_DIR}")
            print(f"📁 [DEBUG] commands_dir: {commands_dir}")
            print(f"📁 [DEBUG] Looking for file: {filepath}")
            print(f"📁 [DEBUG] commands_dir exists: {os.path.exists(commands_dir)}")
            
            # List what's in the commands directory for debugging
            if os.path.exists(commands_dir):
                print(f"📁 [DEBUG] Contents of commands dir: {os.listdir(commands_dir)}")
                for folder_name in os.listdir(commands_dir):
                    folder_path = os.path.join(commands_dir, folder_name)
                    if os.path.isdir(folder_path):
                        print(f"📁 [DEBUG] Contents of {folder_name}: {os.listdir(folder_path)}")
            else:
                print(f"❌ [DEBUG] commands directory NOT FOUND at: {commands_dir}")
                # Try alternative paths
                alt_paths = [
                    os.path.join(os.getcwd(), 'commands'),
                    os.path.join(os.path.dirname(os.path.dirname(BASE_DIR)), 'commands'),
                ]
                for alt in alt_paths:
                    print(f"📁 [DEBUG] Checking alternative path: {alt} - exists: {os.path.exists(alt)}")
                    if os.path.exists(alt):
                        commands_dir = alt
                        filepath = os.path.join(commands_dir, folder, filename)
                        print(f"📁 [DEBUG] Using alternative path: {filepath}")
                        break
            
            if not os.path.exists(filepath):
                # Return more detailed error for debugging
                return jsonify({
                    'error': f'Commands not found for {tab}/{mode}',
                    'debug': {
                        'base_dir': BASE_DIR,
                        'commands_dir': commands_dir,
                        'filepath': filepath,
                        'file_exists': os.path.exists(filepath),
                        'dir_exists': os.path.exists(commands_dir),
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
            
            # 7. CHECK CREDITS
            cost = function_data.get('cost', 0)
            if cost > 0 and (user.credits or 0) < cost:
                return jsonify({'error': f'Insufficient credits. Need {cost} credits', 'code': 'INSUFFICIENT_CREDITS'}), 403
            
            # 8. DEDUCT CREDITS if cost > 0
            if cost > 0:
                user.credits = (user.credits or 0) - cost
                transaction = CreditTransaction(
                    user_id=user.id,
                    amount=-cost,
                    transaction_type='command_usage',
                    description=f'Executed {tab}.{mode}.{action}'
                )
                db.session.add(transaction)
                db.session.commit()
            
            # 9. LOG REQUEST
            log_system_action(user.id, 'command_request', 
                             f"Requested {tab}.{mode}.{action} on {device_info.get('model', 'unknown')}")
            
            # 10. BUILD RESPONSE - ADD THE MISSING FIELDS
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
                'credits_remaining': user.credits or 0,
                'config': function_data.get('config', {}),
                
                # ========== CRITICAL MISSING FIELDS ==========
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
                
                # APK Download Information (for MDM bypass commands)
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

                        # DEBUG: Print what we're sending
            print(f"✅ [DEBUG] Command fetched successfully: {tab}/{mode}/{action}")
            print(f"   type: {response['type']}")
            if response['type'] == 'meta_action':
                print(f"   action_command: '{response['action_command']}'")
            elif response['type'] == 'meta_command':
                print(f"   command: '{response['command']}'")
            
            # 🔒 FORCED ENCRYPTION - ALL command responses MUST be encrypted
            import base64
            session_key = flask_session.get('module_key', '')
            if session_key:
                key = hashlib.sha256(session_key.encode()).digest()
                json_str = json.dumps(response, ensure_ascii=False)
                encrypted = bytes([ord(c) ^ key[i % len(key)] for i, c in enumerate(json_str)])
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
 


    return app

app = create_app()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
