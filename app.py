from flask import send_from_directory
import os
import sys
import secrets
import hashlib
import base64
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
SESSION_DURATION_HOURS = 12
DEVICE_RESET_COST = 2
INACTIVITY_TIMEOUT_MINUTES = 60  # Session expires after 1 hour of inactivity

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

print("\n" + "="*60)
print("🔍 Starting application")
print("="*60)

login_manager = LoginManager()

# ==================== MAINTENANCE MODE FILE ====================
MAINTENANCE_FILE = os.path.join(BASE_DIR, 'maintenance.json')


def is_maintenance_mode():
    """Check if maintenance mode is on"""
    try:
        if os.path.exists(MAINTENANCE_FILE):
            with open(MAINTENANCE_FILE, 'r') as f:
                data = json.load(f)
            return data.get('maintenance', False)
    except:
        pass
    return False


def set_maintenance_mode(enabled, message="Under maintenance"):
    """Set maintenance mode on/off"""
    with open(MAINTENANCE_FILE, 'w') as f:
        json.dump({'maintenance': enabled, 'message': message}, f)


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
        app.config['SECRET_KEY'] = secrets.token_urlsafe(32)

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
                    license_expiry_date=datetime.utcnow() + timedelta(days=3650)
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
                if not admin.check_password(admin_password):
                    admin.set_password(admin_password)
                    db.session.commit()
                    print("✅ Updated admin password from environment")
        else:
            print("⚠️ ADMIN_EMAIL and ADMIN_PASSWORD not set in environment variables")

    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = None

    # ==================== MAINTENANCE MODE MIDDLEWARE ====================
    @app.before_request
    def check_maintenance():
        if is_maintenance_mode():
            # Allow admin routes, login, static, health, and logout
            allowed = ['/login', '/admin-dashboard', '/logout', '/static', '/health', '/favicon.ico']
            if any(request.path.startswith(p) for p in allowed) or request.path.startswith('/api/admin'):
                if current_user.is_authenticated and current_user.is_admin:
                    return None

            if request.path.startswith('/api/'):
                return jsonify({
                    'success': False,
                    'error': 'Maintenance in progress',
                    'maintenance': True
                }), 503

            if 'text/html' in request.headers.get('Accept', ''):
                return render_template('maintanance.html'), 503

    # ==================== API AUTH DECORATOR ====================
    def api_login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.is_authenticated:
                return f(*args, **kwargs)
            user = get_user_from_token()
            if user:
                login_user(user, remember=False)
                return f(*args, **kwargs)
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
                user_agent=request.headers.get('User-Agent', '')[:500]
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
                user_agent=request.headers.get('User-Agent', '')[:500]
            )
            db.session.add(history)
            db.session.commit()
        except Exception as e:
            print(f"Error logging device history: {e}")
            db.session.rollback()

    def send_reset_email(email, reset_token):
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
            <head><meta charset="UTF-8"><title>Password Reset</title>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .container {{ max-width: 600px; margin: 40px auto; padding: 20px; background: #fff; border-radius: 10px; }}
                .button {{ display: inline-block; padding: 12px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; }}
            </style></head>
            <body><div class="container">
                <h2>Password Reset Request</h2>
                <p>We received a request to reset your password for <strong>{email}</strong>.</p>
                <div style="text-align: center;"><a href="{reset_link}" class="button">Reset Password</a></div>
                <p>This link will expire in 1 hour.</p>
                <p>If you didn't request this, please ignore this email.</p>
            </div></body></html>"""

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
                print(f"\n📧 PASSWORD RESET LINK\nReset Link: {reset_link}\n")
                return True
        except Exception as e:
            print(f"❌ Failed to send reset email: {e}")
            return False

    # ==================== MAINTENANCE API ENDPOINTS ====================
    @app.route('/api/admin/toggle-maintenance', methods=['POST'])
    @login_required
    def admin_toggle_maintenance():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        data = request.get_json()
        enabled = data.get('enabled', True)
        message = data.get('message', 'Under maintenance')
        set_maintenance_mode(enabled, message)
        status = 'ON' if enabled else 'OFF'
        log_system_action(current_user.id, 'maintenance', f'Maintenance mode turned {status}')
        return jsonify({'success': True, 'maintenance': enabled, 'status': f'Maintenance mode is now {status}'})

    @app.route('/api/admin/maintenance-status')
    @login_required
    def admin_maintenance_status():
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        return jsonify({'maintenance': is_maintenance_mode()})

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
                    'error': 'License has expired.',
                    'license_expired': True,
                    'license_expiry': user.license_expiry_date.isoformat() if user.license_expiry_date else None
                }), 403

            device_registered = False
            device_id = None
            device_name = None
            hashed_hwid = hash_hwid(hwid) if hwid else None
            session_obj = None

            if hashed_hwid:
                # Find existing device for THIS user
                existing_devices = Device.query.filter_by(
                    user_id=user.id,
                    hwid_hash=hashed_hwid
                ).order_by(Device.id.desc()).all()

                if existing_devices:
                    # Keep only the latest device, deactivate older duplicates
                    if len(existing_devices) > 1:
                        for dup in existing_devices[1:]:
                            dup.is_active = False
                            db_session.add(dup)
                        db_session.flush()

                    existing_device = existing_devices[0]
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
                        device_id=device_id, is_active=True
                    ).filter(UserSession.expires_at > datetime.utcnow()).first()

                    if not session_obj:
                        session_obj = UserSession(
                            user_id=user.id, device_id=device_id,
                            session_token=secrets.token_urlsafe(32),
                            ip_address=get_real_ip(),
                            user_agent=request.headers.get('User-Agent', '')[:500],
                            expires_at=datetime.utcnow() + timedelta(hours=SESSION_DURATION_HOURS),
                            is_active=True
                        )
                        db_session.add(session_obj)

                    log_device_history(user.id, 'login', device_id, device_name, 'Desktop client login')
                else:
                    # New device for this user - allow multiple accounts per hardware
                    active_count = Device.query.filter_by(user_id=user.id, is_active=True).count()
                    if user.device_limit > 0 and active_count >= user.device_limit:
                        return jsonify({
                            'success': False,
                            'error': f'Device limit reached ({active_count}/{user.device_limit})',
                            'code': 'DEVICE_LIMIT_REACHED', 'requires_reset': True
                        }), 403

                    new_device = Device(
                        user_id=user.id, hardware_id=hwid, hwid_hash=hashed_hwid,
                        device_name=f"Desktop-{hwid[:8]}" if hwid else "Unknown-Device",
                        ip_address=get_real_ip(), is_active=True, is_bound=True
                    )
                    db_session.add(new_device)
                    db_session.flush()
                    device_id = new_device.id
                    device_name = new_device.device_name
                    device_registered = True

                    session_obj = UserSession(
                        user_id=user.id, device_id=device_id,
                        session_token=secrets.token_urlsafe(32),
                        ip_address=get_real_ip(),
                        user_agent=request.headers.get('User-Agent', '')[:500],
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
                    user_id=user.id, device_id=None,
                    session_token=secrets.token_urlsafe(32),
                    ip_address=get_real_ip(),
                    user_agent=request.headers.get('User-Agent', '')[:500],
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
                'success': True, 'user_id': user.id, 'username': user.username,
                'email': user.email, 'admission_number': user.admission_number,
                'license_type': user.license_type,
                'license_status': 'active' if user.is_license_valid() else 'expired',
                'license_expiry': user.license_expiry_date.isoformat() if user.license_expiry_date else None,
                'days_remaining': days_remaining, 'device_limit': user.device_limit,
                'device_count': device_count, 'credits': user.credits or 0,
                'is_admin': user.is_admin, 'is_reseller': user.is_reseller,
                'is_banned': user.is_banned, 'license_valid': user.is_license_valid(),
                'session_key': session_key, 'device_registered': device_registered,
                'device_id': device_id, 'device_name': device_name
            }), 200

        except Exception as e:
            db_session.rollback()
            print(f"[ERROR] Validate license error: {e}")
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
                session_token=session_token, is_active=True
            ).filter(UserSession.expires_at > datetime.utcnow()).first()

            if not session_obj:
                return jsonify({'success': False, 'valid': False, 'error': 'Invalid or expired session'}), 401

            # Check 1-hour inactivity timeout
            if session_obj.last_activity:
                inactive_seconds = (datetime.utcnow() - session_obj.last_activity).total_seconds()
                if inactive_seconds > (INACTIVITY_TIMEOUT_MINUTES * 60):
                    session_obj.is_active = False
                    db.session.commit()
                    return jsonify({'success': False, 'valid': False, 'error': 'Session expired due to inactivity'}), 401

            if hwid:
                hashed_hwid = hash_hwid(hwid)
                device = db.session.get(Device, session_obj.device_id)
                if not device or device.hwid_hash != hashed_hwid:
                    return jsonify({'success': False, 'error': 'Session does not match device'}), 403

            session_obj.last_activity = datetime.utcnow()
            db.session.commit()

            return jsonify({
                'success': True, 'valid': True, 'user_id': session_obj.user_id,
                'expires_at': session_obj.expires_at.isoformat(), 'device_id': session_obj.device_id
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500

    # ==================== USER API ENDPOINTS ====================
    @app.route('/api/user/info')
    @api_login_required
    def user_info():
        try:
            user = current_user
            return jsonify({'success': True, 'username': user.username, 'email': user.email,
                           'credits': user.credits or 0, 'admission_number': user.admission_number,
                           'country': user.country or 'Not set', 'is_banned': user.is_banned,
                           'is_active': user.is_active,
                           'created_at': user.created_at.isoformat() if user.created_at else None})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/user/profile')
    @api_login_required
    def user_profile():
        try:
            user = current_user
            days_remaining = 0
            if user.license_expiry_date:
                days_remaining = (user.license_expiry_date - datetime.utcnow()).days
                if days_remaining < 0: days_remaining = 0
            device_count = Device.query.filter_by(user_id=user.id, is_active=True).count()
            return jsonify({'success': True, 'username': user.username, 'email': user.email,
                           'credits': user.credits or 0, 'admission_number': user.admission_number,
                           'country': user.country or 'Not specified', 'is_banned': user.is_banned,
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
                           'license_key': getattr(user, 'license_key', 'N/A')})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/user/devices')
    @api_login_required
    def user_devices():
        try:
            devices = Device.query.filter_by(user_id=current_user.id).order_by(Device.created_at.desc()).all()
            devices_data = [{'id': d.id, 'device_name': d.device_name or 'Unknown Device',
                            'hwid': d.hwid_hash[:16] + '...' if d.hwid_hash else 'N/A',
                            'is_active': d.is_active, 'is_trusted': getattr(d, 'is_trusted', False),
                            'created_at': d.created_at.isoformat() if d.created_at else None,
                            'last_seen': d.last_seen.isoformat() if d.last_seen else None,
                            'ip_address': d.ip_address} for d in devices]
            return jsonify({'success': True, 'devices': devices_data, 'total': len(devices_data),
                           'device_limit': current_user.device_limit})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/user/reset-cost')
    @api_login_required
    def user_reset_cost():
        try:
            user = current_user
            reset_cost = DEVICE_RESET_COST
            user_credits = user.credits or 0
            active_devices = Device.query.filter_by(user_id=user.id, is_active=True).all()
            total_devices = len(active_devices)
            total_cost_all = reset_cost * total_devices
            devices_list = [{'id': d.id, 'name': d.device_name or 'Unknown Device',
                            'hwid_preview': d.hwid_hash[:16] + '...' if d.hwid_hash else 'N/A'} for d in active_devices]
            return jsonify({'success': True, 'cost_per_device': reset_cost, 'total_cost_all': total_cost_all,
                           'user_credits': user_credits, 'total_devices': total_devices,
                           'can_reset_single': user_credits >= reset_cost and total_devices > 0,
                           'can_reset_all': user_credits >= total_cost_all and total_devices > 0,
                           'devices': devices_list})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/user/reset-devices', methods=['POST'])
    @api_login_required
    def user_reset_devices():
        try:
            data = request.get_json() or {}
            device_id = data.get('device_id')
            user = current_user
            reset_cost = DEVICE_RESET_COST
            if not device_id:
                devices = Device.query.filter_by(user_id=user.id, is_active=True).all()
                if not devices: return jsonify({'success': False, 'error': 'No active devices'}), 400
                total_cost = reset_cost * len(devices)
                if (user.credits or 0) < total_cost:
                    return jsonify({'success': False, 'error': f'Need {total_cost} credits'}), 400
                for d in devices:
                    d.is_active = False; d.last_seen = datetime.utcnow()
                    UserSession.query.filter_by(device_id=d.id, is_active=True).update({'is_active': False})
                    log_device_history(user.id, 'reset', d.id, d.device_name, 'Reset all')
                user.credits = (user.credits or 0) - total_cost
                db.session.add(CreditTransaction(user_id=user.id, amount=-total_cost, transaction_type='device_reset',
                                                description=f'Reset all {len(devices)} devices'))
                db.session.commit()
                log_system_action(user.id, 'hwid_reset', f'Reset all {len(devices)} devices')
                return jsonify({'success': True, 'message': f'Successfully reset {len(devices)} devices'})
            else:
                device = Device.query.filter_by(id=device_id, user_id=user.id).first()
                if not device: return jsonify({'success': False, 'error': 'Device not found'}), 404
                if (user.credits or 0) < reset_cost:
                    return jsonify({'success': False, 'error': f'Need {reset_cost} credits'}), 400
                device.is_active = False; device.last_seen = datetime.utcnow()
                UserSession.query.filter_by(device_id=device.id, is_active=True).update({'is_active': False})
                user.credits = (user.credits or 0) - reset_cost
                db.session.add(CreditTransaction(user_id=user.id, amount=-reset_cost, transaction_type='device_reset',
                                                description=f'Reset: {device.device_name}'))
                db.session.commit()
                log_system_action(user.id, 'hwid_reset', f'Reset device: {device.device_name}')
                return jsonify({'success': True, 'message': f'Device "{device.device_name}" reset successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/user/device-history')
    @api_login_required
    def user_device_history():
        try:
            history = DeviceHistory.query.filter_by(user_id=current_user.id).order_by(DeviceHistory.created_at.desc()).limit(50).all()
            history_list = [{'action': h.action, 'reason': h.reason, 'device_name': h.device_name,
                           'created_at': h.created_at.isoformat() if h.created_at else None,
                           'ip_address': h.ip_address} for h in history]
            if not history_list:
                logs = SystemLog.query.filter_by(user_id=current_user.id).order_by(SystemLog.created_at.desc()).limit(50).all()
                for log in logs:
                    history_list.append({'action': log.log_type, 'reason': log.message, 'device_name': None,
                                        'created_at': log.created_at.isoformat() if log.created_at else None,
                                        'ip_address': log.ip_address})
            return jsonify({'success': True, 'history': history_list, 'total': len(history_list)})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/user/change-password', methods=['POST'])
    @api_login_required
    def user_change_password():
        try:
            data = request.get_json()
            current_password = data.get('current_password')
            new_password = data.get('new_password')
            if not current_password or not new_password:
                return jsonify({'success': False, 'error': 'All fields required'}), 400
            if len(new_password) < 6:
                return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
            if not current_user.check_password(current_password):
                return jsonify({'success': False, 'error': 'Current password incorrect'}), 401
            current_user.set_password(new_password)
            db.session.commit()
            log_system_action(current_user.id, 'password_change', 'Password changed')
            return jsonify({'success': True, 'message': 'Password changed successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/user/activity-logs')
    @api_login_required
    def user_activity_logs():
        try:
            logs = SystemLog.query.filter_by(user_id=current_user.id).order_by(SystemLog.created_at.desc()).limit(50).all()
            logs_data = [{'type': l.log_type, 'activity': l.message,
                         'time': l.created_at.strftime('%Y-%m-%d %H:%M:%S') if l.created_at else None,
                         'ip': l.ip_address} for l in logs]
            return jsonify({'success': True, 'logs': logs_data, 'total': len(logs_data)})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/log-detailed', methods=['POST'])
    @api_login_required
    def log_detailed():
        try:
            data = request.get_json()
            tab = data.get('tab', ''); mode = data.get('mode', ''); action = data.get('action', '')
            step_type = data.get('step_type', 'info'); message = data.get('message', '')
            user = current_user
            emoji_map = {'info': 'ℹ️', 'success': '✅', 'error': '❌', 'warning': '⚠️', 'progress': '⏳'}
            emoji = emoji_map.get(step_type, '📝')
            clean_message = message if message.startswith(tuple(emoji_map.values())) else f"{emoji} {message}"
            log_system_action(user.id, f'cmd_{step_type}', f"[{tab}.{mode}.{action}] {clean_message}")
            return jsonify({'success': True}), 200
        except Exception as e:
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
            return jsonify({'success': True, 'total_devices': total_devices, 'device_limit': device_limit,
                           'remaining_slots': remaining, 'credits': user.credits or 0})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    # ==================== WEB ROUTES ====================
    @app.route('/')
    def home():
        if current_user.is_authenticated:
            if current_user.is_admin: return redirect('/admin-dashboard')
            elif current_user.is_reseller: return redirect('/reseller-dashboard')
            else: return redirect('/user-dashboard')
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
        if current_user.is_admin: return redirect('/admin-dashboard')
        if current_user.is_reseller: return redirect('/reseller-dashboard')
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
            if current_user.is_admin: return redirect('/admin-dashboard')
            elif current_user.is_reseller: return redirect('/reseller-dashboard')
            return redirect('/user-dashboard')
        if request.method == 'POST':
            try:
                email = request.form.get('email', '').strip()[:100]
                admission = request.form.get('admission', '').strip()[:20]
                password = request.form.get('password', '')[:128]
                user = None
                if email: user = User.query.filter_by(email=email).first()
                if not user and admission and admission.isdigit():
                    user = User.query.filter_by(admission_number=int(admission)).first()
                if user and user.check_password(password) and not user.is_banned:
                    flask_session.clear()
                    login_user(user)
                    user.last_login = datetime.utcnow()
                    db.session.commit()
                    log_system_action(user.id, 'login', f'Web login: {user.username}')
                    flash('Logged in successfully!', 'success')
                    if user.is_admin: return redirect('/admin-dashboard')
                    elif user.is_reseller: return redirect('/reseller-dashboard')
                    return redirect('/user-dashboard')
                else:
                    flash('Invalid credentials', 'danger')
            except Exception as e:
                db.session.rollback()
                flash('An error occurred', 'danger')
        return render_template('login.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated: return redirect('/user-dashboard')
        if request.method == 'POST':
            try:
                username = request.form.get('username', '').strip()[:80]
                email = request.form.get('email', '').strip().lower()[:100]
                country = request.form.get('country', '').strip()[:50]
                password = request.form.get('password', '')[:128]
                confirm = request.form.get('confirm_password', '')[:128]
                errors = []
                if User.query.filter_by(username=username).first(): errors.append("Username exists")
                if User.query.filter_by(email=email).first(): errors.append("Email registered")
                if password != confirm: errors.append("Passwords don't match")
                if len(password) < 6: errors.append("Password must be 6+ chars")
                if errors:
                    for e in errors: flash(e, 'danger')
                else:
                    admission_number = get_next_admission_number()
                    user = User(username=username, email=email, country=country,
                               admission_number=admission_number, credits=0, device_limit=0)
                    user.set_password(password)
                    db.session.add(user); db.session.commit()
                    log_system_action(user.id, 'register', f'New user: {username}')
                    flash(f'Registration successful! Admission: {admission_number}', 'success')
                    return redirect('/login')
            except Exception as e:
                db.session.rollback()
                flash('Error during registration', 'danger')
        return render_template('register.html')

    @app.route('/logout')
    @login_required
    def logout():
        if current_user.is_authenticated:
            log_system_action(current_user.id, 'logout', f'{current_user.username} logged out')
        logout_user()
        flask_session.clear()
        flash('Logged out', 'success')
        return redirect('/login')

    @app.route('/forgot-password', methods=['GET', 'POST'])
    def forgot_password():
        if current_user.is_authenticated: return redirect('/user-dashboard')
        if request.method == 'POST':
            email = request.form.get('email', '').strip()[:100]
            user = User.query.filter_by(email=email).first()
            if user:
                reset_token = user.generate_reset_token()
                db.session.commit()
                send_reset_email(email, reset_token)
                flash('Reset link sent!', 'success')
            else:
                flash('If account exists, reset link sent.', 'info')
            return redirect(url_for('login'))
        return render_template('forgot_password.html')

    # ✅ FIXED RESET PASSWORD
    @app.route('/reset-password/<token>', methods=['GET', 'POST'])
    def reset_password(token):
        if current_user.is_authenticated:
            logout_user()
            flask_session.clear()
        user = User.query.filter_by(reset_token=token).first()
        if not user or not user.verify_reset_token(token):
            flash('Invalid or expired token.', 'danger')
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
            flash('Password reset! Please login.', 'success')
            return redirect(url_for('login'))
        return render_template('reset_password.html', token=token)

    @app.route('/health')
    def health_check():
        return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat(),
                       'maintenance': is_maintenance_mode()})

    # ==================== COMMAND FETCH WITH ENCRYPTION ====================
    @app.route('/api/get-command', methods=['POST'])
    @api_login_required
    def get_command():
        try:
            data = request.get_json()
            tab = data.get('tab', '').lower()
            mode = data.get('mode', '').lower()
            action = data.get('action', '').lower()
            device_info = data.get('device_info', {})
            print(f"🔍 Command: tab={tab}, mode={mode}, action={action}")

            user = current_user
            if user.is_banned:
                return jsonify({'error': 'Account banned', 'code': 'BANNED'}), 403
            if not user.is_license_valid():
                return jsonify({'error': 'License expired', 'code': 'LICENSE_EXPIRED'}), 403

            tab_folders = {'mediatek': 'mediatek_module', 'unisoc': 'unisoc_module',
                          'xiaomi': 'xiaomi_module', 'samsung': 'samsung_module', 'hxd': 'hxd_module'}
            folder = tab_folders.get(tab)
            if not folder: return jsonify({'error': f'Invalid tab: {tab}'}), 404

            filename = f"{mode}_commands.json"
            commands_dir = os.path.join(BASE_DIR, 'commands')
            filepath = os.path.join(commands_dir, folder, filename)

            if not os.path.exists(filepath):
                return jsonify({'error': f'Commands not found for {tab}/{mode}'}), 404

            with open(filepath, 'r') as f:
                commands_data = json.load(f)

            functions = commands_data.get('functions', {})
            function_data = functions.get(action)
            if not function_data:
                for key, value in functions.items():
                    if key.lower() == action:
                        function_data = value
                        break
                if not function_data:
                    return jsonify({'error': f'Action "{action}" not found'}), 404

            if function_data.get('requires_admin', False) and not user.is_admin:
                return jsonify({'error': 'Admin access required'}), 403

            cost = function_data.get('cost', 0)
            if cost > 0:
                if (user.credits or 0) < cost:
                    return jsonify({'error': f'Need {cost} credits', 'code': 'INSUFFICIENT_CREDITS'}), 403
                user.credits = (user.credits or 0) - cost
                db.session.add(CreditTransaction(user_id=user.id, amount=-cost,
                                                transaction_type='command_usage',
                                                description=f'{tab}.{mode}.{action}'))
                db.session.commit()

            log_system_action(user.id, 'command_request',
                            f"Requested {tab}.{mode}.{action} on {device_info.get('model', 'unknown')}")

            response = {
                'success': True, 'tab': tab, 'mode': mode, 'action': action,
                'type': function_data.get('type', 'adb_commands'),
                'requires_device': function_data.get('requires_device', False),
                'device_type': function_data.get('device_type', 'adb'),
                'progress_steps': function_data.get('progress_steps', []),
                'commands': function_data.get('commands', []),
                'filter_keywords': function_data.get('filter_keywords', {}),
                'unique_filters': function_data.get('unique_filters', {}),
                'success_message': function_data.get('success_message', '✅ Done'),
                'error_message': function_data.get('error_message', '❌ Failed'),
                'timeout': function_data.get('timeout', 60),
                'chunk_size': function_data.get('chunk_size', 4194304),
                'backup_enabled': function_data.get('backup_enabled', False),
                'cost': cost, 'credits_remaining': user.credits or 0,
                'config': function_data.get('config', {}),
                'action_command': function_data.get('action_command', ''),
                'command': function_data.get('command', ''),
                'handshake': function_data.get('handshake', {}),
                'preloader_detection': function_data.get('preloader_detection', {}),
                'boot_methods': function_data.get('boot_methods', []),
                'partitions': function_data.get('partitions', []),
                'reboot': function_data.get('reboot', False),
                'requires_apk': function_data.get('requires_apk', False),
                'apk_name': function_data.get('apk_name', ''),
                'apk_download_url': function_data.get('apk_download_url', ''),
                'apk_package': function_data.get('apk_package', '')
            }

            # ✅ ENCRYPTION
            encrypt_response = request.headers.get('X-Encrypt-Response', '').lower() == 'true' or \
                              data.get('encrypt_response', False)
            if encrypt_response:
                try:
                    session_token = flask_session.get('module_key', '')
                    if session_token:
                        key = hashlib.sha256(session_token.encode()).digest()
                        json_str = json.dumps(response, ensure_ascii=False)
                        encrypted = bytes([ord(c) ^ key[i % len(key)] for i, c in enumerate(json_str)])
                        return jsonify({'encrypted': True, 'data': base64.b64encode(encrypted).decode('utf-8')}), 200
                except:
                    pass

            return jsonify(response), 200
        except Exception as e:
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/check-version', methods=['GET'])
    def check_version():
        version_data = {'latest_version': '1.1.0',
                       'download_url': 'https://my-dolphin-tool-02.onrender.com/download',
                       'changelog': 'Initial release', 'force_update': False}
        return jsonify({'success': True, 'needs_update': False, **version_data}), 200

    # ==================== STATIC PAGES ====================
    @app.route('/supported-models')
    def supported_models(): return render_template('supported_models.html')
    @app.route('/pricing')
    def pricing(): return render_template('pricing.html')
    @app.route('/contact')
    def contact(): return render_template('contact.html')
    @app.route('/faq')
    def faq(): return render_template('faq.html')
    @app.route('/download')
    def download(): return render_template('download.html')

    return app


app = create_app()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
