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
    if not target: return False
    if target.startswith('/'): return True
    return False

def clear_auth_session():
    session.pop('next_url', None)
    session.pop('module_key', None)


# ==================== EMAIL HELPER ====================

def send_reset_email(email, reset_token):
    try:
        config = current_app.config
        smtp_server = config.get('SMTP_SERVER', 'smtp.gmail.com')
        smtp_port = config.get('SMTP_PORT', 587)
        smtp_user = config.get('SMTP_USER')
        smtp_password = config.get('SMTP_PASSWORD')
        from_email = config.get('FROM_EMAIL', smtp_user)
        app_name = config.get('APP_NAME', 'Dolphin Bypass Tool')
        base_url = os.environ.get('BASE_URL') or config.get('BASE_URL') or 'http://localhost:5000'
        
        reset_link = f"{base_url}/auth/reset-password/{reset_token}"
        
        html_content = f"""
        <!DOCTYPE html><html><head><meta charset="UTF-8"><title>Password Reset</title>
        <style>body{{font-family:Arial,sans-serif}}.container{{max-width:600px;margin:40px auto;padding:20px;background:#fff;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}}.button{{display:inline-block;padding:12px 30px;background:#667eea;color:white;text-decoration:none;border-radius:5px;margin:20px 0}}</style>
        </head><body><div class="container"><h2>Password Reset</h2>
        <p>Reset your password for <strong>{email}</strong>.</p>
        <div style="text-align:center"><a href="{reset_link}" class="button">Reset Password</a></div>
        <p>Link expires in 1 hour. If you didn't request this, ignore this email.</p>
        <p>Or copy: {reset_link}</p></div></body></html>"""
        
        if smtp_user and smtp_password and smtp_user != 'your-email@gmail.com':
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"Password Reset - {app_name}"
            msg['From'] = from_email; msg['To'] = email
            msg.attach(MIMEText(html_content, 'html'))
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls(); server.login(smtp_user, smtp_password)
            server.send_message(msg); server.quit()
            print(f"✅ Reset email sent to {email}")
            return True, "Reset email sent"
        else:
            print(f"\n📧 RESET LINK: {reset_link}\n")
            return True, "Reset link generated"
    except Exception as e:
        print(f"❌ Failed: {e}")
        return False, str(e)


# ==================== LOGIN ====================

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin: return redirect(url_for('main.admin_dashboard'))
        elif current_user.is_reseller: return redirect(url_for('main.reseller_dashboard'))
        return redirect(url_for('main.dashboard_page'))
    
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip()
            username = request.form.get('username', '').strip()
            admission = request.form.get('admission', '').strip()
            password = request.form.get('password', '')
            
            user = None
            if email: user = User.query.filter_by(email=email).first()
            if not user and username: user = User.query.filter_by(username=username).first()
            if not user and admission:
                try: user = User.query.filter_by(admission_number=int(admission)).first()
                except: pass
            
            if not user or not user.check_password(password):
                flash('Invalid credentials', 'danger')
                return render_template('login.html')
            
            if user.is_banned:
                flash('Account is banned', 'danger')
                return render_template('login.html')
            
            session_key = secrets.token_urlsafe(32)
            session['module_key'] = session_key
            user.current_session_key = session_key
            db.session.commit()
            
            login_user(user, remember=request.form.get('remember_me') == 'on')
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            flash('Logged in successfully!', 'success')
            if user.is_admin: return redirect(url_for('main.admin_dashboard'))
            elif user.is_reseller: return redirect(url_for('main.reseller_dashboard'))
            return redirect(url_for('main.dashboard_page'))
        except Exception as e:
            flash('An error occurred', 'danger')
    return render_template('login.html')


# ==================== REGISTER ====================

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard_page'))
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            confirm = request.form.get('confirm_password', '')
            
            errors = []
            if User.query.filter_by(username=username).first(): errors.append("Username exists")
            if User.query.filter_by(email=email).first(): errors.append("Email registered")
            if password != confirm: errors.append("Passwords don't match")
            if len(password) < 6: errors.append("Password must be 6+ chars")
            
            if errors:
                for e in errors: flash(e, 'danger')
                return render_template('register.html')
            
            last = User.query.order_by(User.admission_number.desc()).first()
            admission_number = (last.admission_number + 1) if last else 1000
            
            user = User(username=username, email=email, admission_number=admission_number, credits=0)
            user.set_password(password)
            db.session.add(user); db.session.commit()
            
            flash(f'Registered! Admission: {admission_number}', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            flash('Error during registration', 'danger')
    return render_template('register.html')


# ==================== LOGOUT ====================

@auth_bp.route('/logout')
@login_required
def logout():
    clear_auth_session()
    logout_user()
    flash('Logged out', 'info')
    return redirect(url_for('auth.login'))


# ==================== PASSWORD RESET (WORKING) ====================

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password_page():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard_page'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        user = User.query.filter_by(email=email).first()
        if user:
            reset_token = user.generate_reset_token()
            db.session.commit()
            send_reset_email(email, reset_token)
            flash('Reset link sent to your email!', 'success')
        else:
            flash('If account exists, reset link sent.', 'info')
        return redirect(url_for('auth.login'))
    
    session.pop('next_url', None)
    return render_template('forgot_password.html')


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_page(token):
    # Log out any existing user
    if current_user.is_authenticated:
        logout_user()
        session.clear()
    
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or not user.verify_reset_token(token):
        flash('Invalid or expired reset token.', 'danger')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        
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
        return redirect(url_for('auth.login'))
    
    return render_template('reset_password.html', token=token)
