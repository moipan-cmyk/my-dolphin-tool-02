# routes/auth_routes.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import smtplib
import os
import traceback
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from database import db, User, SystemLog, Device, UserSession, DeviceHistory, CreditTransaction

auth_bp = Blueprint('auth', __name__)


# ==================== HELPER FUNCTIONS ====================

def is_safe_redirect_url(target):
    """Check if a redirect URL is safe (prevents open redirect vulnerabilities)"""
    if not target:
        return False
    # Allow relative URLs
    if target.startswith('/'):
        return True
    # Block external URLs
    if target.startswith('http://') or target.startswith('https://'):
        return False
    return False

def clear_auth_session():
    """Clear authentication-related session variables"""
    session.pop('next_url', None)
    session.pop('module_key', None)


# ==================== EMAIL HELPER FUNCTIONS ====================

def send_reset_email(email, reset_token):
    """Send password reset email to user"""
    try:
        config = current_app.config
        
        smtp_server = config.get('SMTP_SERVER', 'smtp.gmail.com')
        smtp_port = config.get('SMTP_PORT', 587)
        smtp_user = config.get('SMTP_USER')
        smtp_password = config.get('SMTP_PASSWORD')
        from_email = config.get('FROM_EMAIL', smtp_user)
        app_name = config.get('APP_NAME', 'Dolphin Bypass Tool')
        base_url = config.get('BASE_URL', 'http://localhost:5000')
        
        reset_link = f"{base_url}/reset-password/{reset_token}"
        subject = f"Password Reset Request - {app_name}"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Password Reset</title>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .container {{ max-width: 600px; margin: 40px auto; padding: 20px; background: #fff; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .header {{ text-align: center; padding: 20px; border-bottom: 2px solid #00b4d8; }}
                .header h1 {{ color: #00b4d8; }}
                .button {{ display: inline-block; padding: 12px 30px; background: #00b4d8; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
                .footer {{ text-align: center; padding: 20px; font-size: 12px; color: #666; }}
                .warning {{ background: #fff3cd; padding: 12px; margin: 20px 0; border-left: 4px solid #ffc107; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 {app_name}</h1>
                </div>
                <div class="content">
                    <h2>Password Reset Request</h2>
                    <p>We received a request to reset your password for <strong>{email}</strong>.</p>
                    <div style="text-align: center;">
                        <a href="{reset_link}" class="button">Reset Password</a>
                    </div>
                    <div class="warning">
                        ⚠️ This link will expire in 1 hour.
                    </div>
                    <p>If the button doesn't work, copy this link: <br>{reset_link}</p>
                </div>
                <div class="footer">
                    <p>&copy; 2024 {app_name}. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        if smtp_user and smtp_password and smtp_user != 'your-email@gmail.com':
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = from_email
            msg['To'] = email
            msg.attach(MIMEText(html_content, 'html'))
            
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
            server.quit()
            print(f"✅ Password reset email sent to {email}")
            return True, "Reset email sent"
        else:
            print(f"\n{'='*60}")
            print(f"📧 PASSWORD RESET LINK (Development Mode)")
            print(f"{'='*60}")
            print(f"Email: {email}")
            print(f"Reset Link: {reset_link}")
            print(f"{'='*60}\n")
            return True, "Reset link generated"
            
    except Exception as e:
        print(f"❌ Failed to send reset email: {e}")
        traceback.print_exc()
        return False, str(e)


# ==================== WEB ROUTES ====================

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    # If already logged in, redirect to appropriate dashboard
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('main.admin_dashboard'))
        elif current_user.is_reseller:
            return redirect(url_for('main.reseller_dashboard'))
        return redirect(url_for('main.dashboard_page'))
    
    # Get next URL - prevent redirect loops
    next_url = session.pop('next_url', request.args.get('next'))
    
    # CRITICAL: Prevent redirect to login/register pages (would cause infinite loop)
    if next_url:
        # Block redirects to auth pages
        blocked_paths = ['/login', '/register', '/forgot-password', '/reset-password']
        for blocked in blocked_paths:
            if blocked in next_url or next_url.endswith(blocked):
                next_url = None
                break
        # Also block external URLs
        if not is_safe_redirect_url(next_url):
            next_url = None
    
    if request.method == 'POST':
        try:
            # Get form data - supports email, username, OR admission number
            email = request.form.get('email', '').strip()
            username = request.form.get('username', '').strip()
            admission = request.form.get('admission', '').strip()
            password = request.form.get('password', '')
            
            print(f"[DEBUG] Login attempt - Email: {email}, Username: {username}, Admission: {admission}")
            
            # Find user by email, username, or admission number
            user = None
            
            if email:
                user = User.query.filter_by(email=email).first()
                if user:
                    print(f"[DEBUG] User found by email: {user.username}")
            
            if not user and username:
                user = User.query.filter_by(username=username).first()
                if user:
                    print(f"[DEBUG] User found by username: {user.username}")
            
            if not user and admission:
                try:
                    admission_int = int(admission)
                    user = User.query.filter_by(admission_number=admission_int).first()
                    if user:
                        print(f"[DEBUG] User found by admission: {user.username}")
                except (ValueError, TypeError):
                    print(f"[DEBUG] Invalid admission number format: {admission}")
                    flash('Invalid admission number format', 'danger')
                    return render_template('login.html')
            
            if not user:
                print(f"[DEBUG] No user found")
                flash('Invalid credentials', 'danger')
                return render_template('login.html')
            
            # Check password
            if not user.check_password(password):
                print(f"[DEBUG] Password check failed for user: {user.username}")
                flash('Invalid credentials', 'danger')
                return render_template('login.html')
            
            # Check if banned
            if user.is_banned:
                print(f"[DEBUG] User is banned: {user.username}")
                flash('Account is banned. Please contact support.', 'danger')
                return render_template('login.html')
            
            # Generate session key for module encryption
            session_key = secrets.token_urlsafe(32)
            session['module_key'] = session_key
            
            # Store in database
            user.current_session_key = session_key
            user.last_session_key = session_key
            db.session.commit()
            
            # Login user
            login_user(user, remember=request.form.get('remember_me') == 'on')
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            print(f"[DEBUG] User logged in successfully: {user.username}")
            
            # Log the login
            log = SystemLog(
                user_id=user.id,
                log_type='info',
                message='User logged in successfully',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            db.session.add(log)
            db.session.commit()
            
            flash('Logged in successfully!', 'success')
            
            # Redirect based on user role and next_url
            if next_url:
                return redirect(next_url)
            
            if user.is_admin:
                return redirect(url_for('main.admin_dashboard'))
            elif user.is_reseller:
                return redirect(url_for('main.reseller_dashboard'))
            else:
                return redirect(url_for('main.dashboard_page'))
                
        except Exception as e:
            print(f"[ERROR] Login error: {e}")
            traceback.print_exc()
            flash('An error occurred during login. Please try again.', 'danger')
            return render_template('login.html')
    
    return render_template('login.html')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard_page'))
    
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip().lower()
            admission = request.form.get('admission', '').strip()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            print(f"[DEBUG] Registration attempt - Username: {username}, Email: {email}, Admission: {admission}")
            
            # Validation
            errors = []
            
            if not username:
                errors.append("Username is required")
            elif len(username) < 3:
                errors.append("Username must be at least 3 characters")
            elif len(username) > 80:
                errors.append("Username must be less than 80 characters")
            elif User.query.filter_by(username=username).first():
                errors.append("Username already exists")
            
            if not email:
                errors.append("Email is required")
            elif '@' not in email or '.' not in email:
                errors.append("Invalid email format")
            elif User.query.filter_by(email=email).first():
                errors.append("Email already registered")
            
            # Handle admission number
            admission_number = None
            if admission:
                try:
                    admission_number = int(admission)
                    if User.query.filter_by(admission_number=admission_number).first():
                        errors.append("Admission number already registered")
                except ValueError:
                    errors.append("Invalid admission number format")
            else:
                # Auto-generate admission number
                last_user = User.query.order_by(User.admission_number.desc()).first()
                admission_number = (last_user.admission_number + 1) if last_user else 1000
                print(f"[DEBUG] Auto-generated admission number: {admission_number}")
            
            if not password:
                errors.append("Password is required")
            elif len(password) < 6:
                errors.append("Password must be at least 6 characters")
            
            if password != confirm_password:
                errors.append("Passwords do not match")
            
            if errors:
                for error in errors:
                    flash(error, 'danger')
                return render_template('register.html')
            
            # Create new user
            user = User(
                username=username,
                email=email,
                admission_number=admission_number,
                credits=0
            )
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            
            print(f"[DEBUG] User registered successfully: {username}")
            
            # Log registration
            log = SystemLog(
                user_id=user.id,
                log_type='info',
                message=f'New user registered (Admission: {admission_number})',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            db.session.add(log)
            db.session.commit()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            print(f"[ERROR] Registration error: {e}")
            traceback.print_exc()
            flash('An error occurred during registration. Please try again.', 'danger')
            return render_template('register.html')
    
    return render_template('register.html')


@auth_bp.route('/logout')
@login_required
def logout():
    if current_user.is_authenticated:
        print(f"[DEBUG] User logging out: {current_user.username}")
        
        # Clear session
        clear_auth_session()
        
        log = SystemLog(
            user_id=current_user.id,
            log_type='info',
            message='User logged out',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        db.session.add(log)
        db.session.commit()
    
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


# ==================== PASSWORD RESET ROUTES ====================

@auth_bp.route('/forgot-password', methods=['GET'])
def forgot_password_page():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard_page'))
    # Clear any pending next_url to prevent redirect loops
    session.pop('next_url', None)
    return render_template('forgot_password.html')


@auth_bp.route('/reset-password/<token>', methods=['GET'])
def reset_password_page(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard_page'))
    # Clear any pending next_url to prevent redirect loops
    session.pop('next_url', None)
    return render_template('reset_password.html', token=token)


# ==================== API ENDPOINTS FOR DESKTOP CLIENT ====================

@auth_bp.route('/api/validate-license', methods=['POST'])
def validate_license():
    """API endpoint for desktop client to validate license"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No JSON data received'}), 400
        
        print(f"[DEBUG] Validate license request: {data}")
        
        email = data.get('email')
        username = data.get('username')
        admission = data.get('admission')
        admission_number = data.get('admission_number')
        password = data.get('password')
        
        if not password:
            return jsonify({'success': False, 'error': 'Password required'}), 400
        
        # Find user
        user = None
        if email:
            user = User.query.filter_by(email=email).first()
        elif username:
            user = User.query.filter_by(username=username).first()
        elif admission:
            try:
                admission_int = int(admission)
                user = User.query.filter_by(admission_number=admission_int).first()
            except (ValueError, TypeError):
                pass
        elif admission_number:
            try:
                admission_int = int(admission_number)
                user = User.query.filter_by(admission_number=admission_int).first()
            except (ValueError, TypeError):
                pass
        
        if not user:
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        if not user.check_password(password):
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        if user.is_banned:
            return jsonify({'success': False, 'error': 'Account is banned', 'is_banned': True}), 403
        
        license_valid = user.is_license_valid()
        device_count = user.get_active_devices_count()
        
        # Calculate days remaining
        days_remaining = None
        if user.license_expiry_date:
            days_remaining = (user.license_expiry_date - datetime.utcnow()).days
            if days_remaining < 0:
                days_remaining = 0
        
        # Generate session key for API client
        session_key = secrets.token_urlsafe(32)
        session['module_key'] = session_key
        
        user.current_session_key = session_key
        db.session.commit()
        
        print(f"[DEBUG] License validated for user: {user.username}")
        
        return jsonify({
            'success': True,
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'admission_number': user.admission_number,
            'license_type': user.license_type,
            'license_status': user.license_status if license_valid else 'expired',
            'license_expiry': user.license_expiry_date.isoformat() if user.license_expiry_date else None,
            'days_remaining': days_remaining,
            'device_limit': user.device_limit,
            'device_count': device_count,
            'credits': user.credits or 0,
            'is_admin': user.is_admin,
            'is_reseller': user.is_reseller,
            'is_banned': user.is_banned,
            'license_valid': license_valid,
            'session_key': session_key
        }), 200
        
    except Exception as e:
        print(f"[ERROR] Validate license error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@auth_bp.route('/api/get-session-key', methods=['GET'])
@login_required
def get_session_key():
    """Return the current session key for module decryption"""
    try:
        session_key = session.get('module_key')
        
        if not session_key:
            session_key = secrets.token_urlsafe(32)
            session['module_key'] = session_key
            current_user.current_session_key = session_key
            db.session.commit()
        
        return jsonify({
            'success': True,
            'session_key': session_key
        }), 200
        
    except Exception as e:
        print(f"[ERROR] Get session key error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@auth_bp.route('/api/user/credits', methods=['GET'])
def get_user_credits():
    """API endpoint to get user credits"""
    try:
        email = request.args.get('email')
        username = request.args.get('username')
        admission = request.args.get('admission')
        
        user = None
        if email:
            user = User.query.filter_by(email=email).first()
        elif username:
            user = User.query.filter_by(username=username).first()
        elif admission:
            try:
                admission_int = int(admission)
                user = User.query.filter_by(admission_number=admission_int).first()
            except (ValueError, TypeError):
                pass
        
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        return jsonify({
            'success': True,
            'credits': user.credits or 0,
            'username': user.username,
            'email': user.email,
            'license_type': user.license_type,
            'admission_number': user.admission_number
        }), 200
        
    except Exception as e:
        print(f"[ERROR] Get credits error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@auth_bp.route('/api/user/deduct-credits', methods=['POST'])
def deduct_user_credits():
    """API endpoint to deduct credits from user"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No JSON data received'}), 400
        
        email = data.get('email')
        username = data.get('username')
        admission = data.get('admission')
        amount = data.get('amount', 0)
        description = data.get('description', 'Credit deduction')
        action = data.get('action', 'usage')
        
        if amount <= 0:
            return jsonify({'success': False, 'error': 'Invalid amount'}), 400
        
        user = None
        if email:
            user = User.query.filter_by(email=email).first()
        elif username:
            user = User.query.filter_by(username=username).first()
        elif admission:
            try:
                admission_int = int(admission)
                user = User.query.filter_by(admission_number=admission_int).first()
            except (ValueError, TypeError):
                pass
        
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        if (user.credits or 0) < amount:
            return jsonify({
                'success': False,
                'error': f'Insufficient credits. Need {amount}, have {user.credits or 0}'
            }), 402
        
        success = user.deduct_credits(amount, transaction_type=action, description=description)
        
        if success:
            db.session.commit()
            return jsonify({
                'success': True,
                'message': f'Deducted {amount} credits',
                'new_balance': user.credits or 0
            }), 200
        else:
            return jsonify({'success': False, 'error': 'Failed to deduct credits'}), 500
        
    except Exception as e:
        print(f"[ERROR] Deduct credits error: {e}")
        traceback.print_exc()
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== PASSWORD RESET API ENDPOINTS ====================

@auth_bp.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    """Handle forgot password request"""
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'success': False, 'error': 'Email is required'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            return jsonify({
                'success': True,
                'message': 'If an account exists, a reset link has been sent.'
            }), 200
        
        if user.is_banned:
            return jsonify({'success': False, 'error': 'Account is banned'}), 403
        
        reset_token = user.generate_reset_token()
        db.session.commit()
        
        success, message = send_reset_email(email, reset_token)
        
        return jsonify({
            'success': True,
            'message': 'Password reset link has been sent to your email.'
        }), 200
        
    except Exception as e:
        print(f"[ERROR] Forgot password error: {e}")
        traceback.print_exc()
        db.session.rollback()
        return jsonify({'success': False, 'error': 'An error occurred'}), 500


@auth_bp.route('/api/validate-reset-token', methods=['POST'])
def validate_reset_token():
    """Validate if a reset token is still valid"""
    try:
        data = request.get_json()
        token = data.get('token')
        
        if not token:
            return jsonify({'success': False, 'error': 'Token required'}), 400
        
        user = User.query.filter_by(reset_token=token).first()
        
        if not user:
            return jsonify({'success': False, 'error': 'Invalid token', 'valid': False}), 200
        
        if user.verify_reset_token(token):
            return jsonify({'success': True, 'valid': True, 'email': user.email}), 200
        else:
            return jsonify({'success': False, 'error': 'Token expired', 'valid': False, 'expired': True}), 200
        
    except Exception as e:
        print(f"[ERROR] Validate token error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'An error occurred'}), 500


@auth_bp.route('/api/reset-password', methods=['POST'])
def reset_password():
    """Handle password reset with token"""
    try:
        data = request.get_json()
        token = data.get('token')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        
        if not token:
            return jsonify({'success': False, 'error': 'Reset token required'}), 400
        
        if not password:
            return jsonify({'success': False, 'error': 'New password required'}), 400
        
        if password != confirm_password:
            return jsonify({'success': False, 'error': 'Passwords do not match'}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
        
        user = User.query.filter_by(reset_token=token).first()
        
        if not user:
            return jsonify({'success': False, 'error': 'Invalid or expired reset token'}), 400
        
        if not user.verify_reset_token(token):
            return jsonify({'success': False, 'error': 'Reset token has expired'}), 400
        
        if user.is_banned:
            return jsonify({'success': False, 'error': 'Account is banned'}), 403
        
        user.set_password(password)
        user.clear_reset_token()
        db.session.commit()
        
        log = SystemLog(
            user_id=user.id,
            log_type='info',
            message='Password reset via email',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        db.session.add(log)
        db.session.commit()
        
        print(f"[DEBUG] Password reset successful for user: {user.email}")
        
        return jsonify({'success': True, 'message': 'Password reset successfully'}), 200
        
    except Exception as e:
        print(f"[ERROR] Reset password error: {e}")
        traceback.print_exc()
        db.session.rollback()
        return jsonify({'success': False, 'error': 'An error occurred'}), 500


@auth_bp.route('/debug-session')
@login_required
def debug_session():
    """Debug endpoint to check session"""
    return jsonify({
        'authenticated': current_user.is_authenticated,
        'user_id': current_user.id,
        'username': current_user.username,
        'email': current_user.email,
        'is_admin': current_user.is_admin,
        'is_reseller': current_user.is_reseller,
        'is_banned': current_user.is_banned,
        'license_type': current_user.license_type,
        'credits': current_user.credits,
        'device_limit': current_user.device_limit,
        'has_session_key': 'module_key' in session,
        'session': {
            'is_active': True,
            'user_agent': request.headers.get('User-Agent')
        }
    })


# ==================== REDIRECT LOOP DEBUG ENDPOINT ====================

@auth_bp.route('/debug-redirects')
def debug_redirects():
    """Debug endpoint to check what's causing redirect loops"""
    return jsonify({
        'current_user_authenticated': current_user.is_authenticated,
        'current_user_id': current_user.id if current_user.is_authenticated else None,
        'session_keys': list(session.keys()),
        'request_path': request.path,
        'request_full_path': request.full_path,
        'request_args': request.args.to_dict(),
        'next_url': session.get('next_url'),
        'referrer': request.headers.get('Referer'),
        'user_agent': request.headers.get('User-Agent'),
        'endpoint': request.endpoint,
        'blueprint': request.blueprint
    })