from flask import Blueprint, render_template, redirect, flash, request, send_file, session, current_app, url_for
from flask_login import login_required, current_user, logout_user
from utils.decorators import admin_required, reseller_required
import os

main_bp = Blueprint('main', __name__)

# ==================== PROTECTED ADMINS ====================
PROTECTED_ADMINS = ['clintonmoipan34@gmail.com']

@main_bp.route('/')
def index():
    return render_template('home.html')

@main_bp.route('/login')
def login_page():
    return redirect(url_for('auth.login'))

@main_bp.route('/register')
def register_page():
    if current_user.is_authenticated:
        return redirect('/dashboard')
    return redirect(url_for('auth.register'))

@main_bp.route('/forgot-password')
def forgot_password_page():
    if current_user.is_authenticated:
        return redirect('/dashboard')
    return redirect(url_for('auth.forgot_password_page'))

@main_bp.route('/reset-password/<token>')
def reset_password_page(token):
    if current_user.is_authenticated:
        return redirect('/dashboard')
    return redirect(url_for('auth.reset_password_page', token=token))

@main_bp.route('/supported-models')
def supported_models_page():
    return render_template('supported_models.html')

@main_bp.route('/pricing')
def pricing_page():
    return render_template('pricing.html')

@main_bp.route('/contact', methods=['GET', 'POST'])
def contact_page():
    from utils.helpers import log_system
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')
        if not all([name, email, subject, message]):
            flash('All fields are required', 'error')
            return redirect('/contact')
        try:
            log_system(None, 'contact_form', f'Contact from {name} ({email}): {subject}', request)
            flash('Thank you for your message. We will get back to you soon!', 'success')
        except Exception as e:
            print(f"Contact form error: {e}")
            flash('An error occurred. Please try again.', 'error')
        return redirect('/contact')
    return render_template('contact.html')

@main_bp.route('/resellers')
def resellers_page():
    return render_template('resellers.html')

@main_bp.route('/documentation')
def documentation_page():
    return render_template('documentation.html')

@main_bp.route('/faq')
def faq_page():
    return render_template('faq.html')

@main_bp.route('/download')
def download_page():
    return render_template('download.html')

@main_bp.route('/download/file')
def download_file():
    try:
        file_path = os.path.join(main_bp.root_path, '..', 'static', 'downloads', 'dolphin_bypass_tool.exe')
        if not os.path.exists(file_path):
            return redirect('https://github.com/clintonmoipan34-stack/My-mdm-Tool/releases/latest')
        return send_file(file_path, as_attachment=True, download_name='Dolphin_Bypass_Tool.exe')
    except Exception as e:
        print(f"Download error: {e}")
        flash('Download failed. Please try again or use GitHub link.', 'error')
        return redirect('/download')

@main_bp.route('/dashboard')
@login_required
def dashboard_page():
    """Regular user dashboard"""
    try:
        return render_template('user_dashboard.html')
    except Exception as e:
        print(f"[ERROR] Dashboard template error: {e}")
        flash('Error loading dashboard. Please contact support.', 'error')
        return redirect('/')

@main_bp.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    try:
        return render_template('admin_dashboard.html')
    except Exception as e:
        print(f"[ERROR] Admin dashboard template error: {e}")
        flash('Error loading admin dashboard. Please contact support.', 'error')
        return redirect('/')

@main_bp.route('/reseller/dashboard')
@login_required
@reseller_required
def reseller_dashboard():
    """Reseller dashboard"""
    try:
        return render_template('reseller_dashboard.html')
    except Exception as e:
        print(f"[ERROR] Reseller dashboard template error: {e}")
        flash('Error loading reseller dashboard. Please contact support.', 'error')
        return redirect('/')

@main_bp.route('/logout')
def logout_page():
    """Logout user and clear session"""
    if current_user.is_authenticated:
        print(f"User {current_user.username} logging out")
    
    logout_user()
    
    session.pop('_user_id', None)
    session.pop('_fresh', None)
    session.pop('user_id', None)
    session.clear()
    
    response = redirect(url_for('auth.login'))
    
    response.delete_cookie('remember_token')
    
    session_cookie = current_app.config.get('SESSION_COOKIE_NAME', 'session')
    response.delete_cookie(session_cookie)
    
    flash('Logged out successfully', 'success')
    
    print(f"Logout completed, redirected to login")
    
    return response