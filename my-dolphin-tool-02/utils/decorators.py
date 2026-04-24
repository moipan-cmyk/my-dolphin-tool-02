# utils/decorators.py
from functools import wraps
from flask import flash, redirect, request, session, jsonify
from flask_login import current_user

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is authenticated
        if not current_user.is_authenticated:
            # For API requests, return JSON
            if request.path.startswith('/api/'):
                return jsonify({
                    'success': False,
                    'error': 'Authentication required',
                    'code': 'UNAUTHORIZED'
                }), 401
            
            # For web requests, store next URL and redirect
            session['next_url'] = request.url
            flash('Please log in first', 'error')
            return redirect('/login')
        
        # Check if user is admin (either by email or is_admin flag)
        is_admin = getattr(current_user, 'is_admin', False)
        if current_user.email == 'snapdragonspd@gmail.com' or is_admin:
            return f(*args, **kwargs)
        
        # Not admin - deny access
        flash('Admin access required', 'error')
        return redirect('/dashboard')
    
    return decorated_function

def reseller_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is authenticated
        if not current_user.is_authenticated:
            # For API requests, return JSON
            if request.path.startswith('/api/'):
                return jsonify({
                    'success': False,
                    'error': 'Authentication required',
                    'code': 'UNAUTHORIZED'
                }), 401
            
            # For web requests, store next URL and redirect
            session['next_url'] = request.url
            flash('Please log in first', 'error')
            return redirect('/login')
        
        # Check if user is reseller or admin or super admin
        is_reseller = getattr(current_user, 'is_reseller', False)
        is_admin = getattr(current_user, 'is_admin', False)
        
        if is_reseller or is_admin or current_user.email == 'snapdragonspd@gmail.com':
            return f(*args, **kwargs)
        
        # Not reseller - deny access
        flash('Reseller access required', 'error')
        return redirect('/dashboard')
    
    return decorated_function

# Add these new decorators for better control
def login_required_with_device_limit(f):
    """Decorator that checks login and device limit"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is authenticated
        if not current_user.is_authenticated:
            # For API requests, return JSON
            if request.path.startswith('/api/'):
                return jsonify({
                    'success': False,
                    'error': 'Authentication required',
                    'code': 'UNAUTHORIZED'
                }), 401
            
            # For web requests, store next URL and redirect
            session['next_url'] = request.url
            flash('Please log in first', 'error')
            return redirect('/login')
        
        # Check device limit
        from app import check_device_limit_and_access
        can_access, message = check_device_limit_and_access(current_user.id)
        
        if not can_access:
            # For API requests
            if request.path.startswith('/api/'):
                return jsonify({
                    'success': False,
                    'error': message,
                    'code': 'DEVICE_LIMIT_REACHED',
                    'action_required': 'reset_device'
                }), 403
            
            # For web requests
            flash(message, 'warning')
            return redirect('/user/devices')
        
        return f(*args, **kwargs)
    
    return decorated_function

def public_route(f):
    """Decorator for public routes that don't require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Just pass through - no authentication required
        return f(*args, **kwargs)
    return decorated_function

def prevent_redirect_loop(f):
    """Decorator to prevent redirect loops on auth pages"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Clear next_url if it points to the same page
        next_url = session.get('next_url')
        if next_url and request.path in next_url:
            session.pop('next_url', None)
        return f(*args, **kwargs)
    return decorated_function