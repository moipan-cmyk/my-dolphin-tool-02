# form_routes.py - Manual form handling without WTForms
# forms.py - Combined file with both form classes and handlers
from flask import request
from flask_login import login_user
from database import db, User
from datetime import datetime


# ==================== FORM CLASSES (for auth_routes.py) ====================

class LoginForm:
    """Login form class for auth_routes.py"""
    def __init__(self):
        self.username = None
        self.password = None
        self.remember_me = None
        self.errors = {}
    
    def validate_on_submit(self):
        """Validate form data from request"""
        self.username = request.form.get('username')
        self.password = request.form.get('password')
        self.remember_me = request.form.get('remember_me') == 'on'
        
        self.errors = {}
        
        if not self.username:
            self.errors['username'] = ['Username is required']
        
        if not self.password:
            self.errors['password'] = ['Password is required']
        
        return len(self.errors) == 0


class RegistrationForm:
    """Registration form class for auth_routes.py"""
    def __init__(self):
        self.username = None
        self.email = None
        self.password = None
        self.confirm_password = None
        self.errors = {}
    
    def validate_on_submit(self):
        """Validate form data from request"""
        self.username = request.form.get('username')
        self.email = request.form.get('email')
        self.password = request.form.get('password')
        self.confirm_password = request.form.get('confirm_password')
        
        self.errors = {}
        
        # Username validation
        if not self.username:
            self.errors['username'] = ['Username is required']
        elif len(self.username) < 3:
            self.errors['username'] = ['Username must be at least 3 characters']
        elif len(self.username) > 80:
            self.errors['username'] = ['Username must be less than 80 characters']
        elif User.query.filter_by(username=self.username).first():
            self.errors['username'] = ['Username already taken']
        
        # Email validation
        if not self.email:
            self.errors['email'] = ['Email is required']
        elif '@' not in self.email or '.' not in self.email:
            self.errors['email'] = ['Invalid email address']
        elif User.query.filter_by(email=self.email).first():
            self.errors['email'] = ['Email already registered']
        
        # Password validation
        if not self.password:
            self.errors['password'] = ['Password is required']
        elif len(self.password) < 6:
            self.errors['password'] = ['Password must be at least 6 characters']
        
        # Confirm password validation
        if self.password != self.confirm_password:
            self.errors['confirm_password'] = ['Passwords do not match']
        
        return len(self.errors) == 0


# ==================== FORM HANDLING FUNCTIONS ====================

def handle_login_form(username, password, remember_me):
    """Handle login form validation and processing"""
    # Validation
    if not username or not password:
        return False, "Username and password are required"
    
    # Find user
    user = User.query.filter_by(username=username).first()
    
    if not user or not user.check_password(password):
        return False, "Invalid username or password"
    
    # Check if banned
    if user.is_banned:
        return False, "Account is banned. Please contact support."
    
    # Login user
    login_user(user, remember=remember_me)
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    return True, user


def handle_registration_form(username, email, password, confirm_password):
    """Handle registration form processing"""
    # Validate
    errors = validate_registration_form(username, email, password, confirm_password)
    
    if errors:
        return False, errors
    
    # Create user
    last_user = User.query.order_by(User.admission_number.desc()).first()
    admission_number = (last_user.admission_number + 1) if last_user else 1000
    
    user = User(
        username=username,
        email=email,
        admission_number=admission_number,
        credits=0
    )
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    
    return True, user


def validate_registration_form(username, email, password, confirm_password):
    """Validate registration form data"""
    errors = []
    
    # Username validation
    if not username:
        errors.append("Username is required")
    elif len(username) < 3:
        errors.append("Username must be at least 3 characters")
    elif len(username) > 80:
        errors.append("Username must be less than 80 characters")
    elif User.query.filter_by(username=username).first():
        errors.append("Username already exists")
    
    # Email validation
    if not email:
        errors.append("Email is required")
    elif '@' not in email or '.' not in email:
        errors.append("Invalid email format")
    elif User.query.filter_by(email=email).first():
        errors.append("Email already registered")
    
    # Password validation
    if not password:
        errors.append("Password is required")
    elif len(password) < 6:
        errors.append("Password must be at least 6 characters")
    
    # Confirm password validation
    if password != confirm_password:
        errors.append("Passwords do not match")
    
    return errors


def handle_password_change(user, current_password, new_password, confirm_password):
    """Handle password change"""
    errors = validate_password_change(user, current_password, new_password, confirm_password)
    
    if errors:
        return False, errors
    
    user.set_password(new_password)
    db.session.commit()
    
    return True, "Password changed successfully"


def validate_password_change(user, current_password, new_password, confirm_password):
    """Validate password change form"""
    errors = []
    
    if not current_password:
        errors.append("Current password is required")
    elif not user.check_password(current_password):
        errors.append("Current password is incorrect")
    
    if not new_password:
        errors.append("New password is required")
    elif len(new_password) < 6:
        errors.append("New password must be at least 6 characters")
    
    if new_password != confirm_password:
        errors.append("New passwords do not match")
    
    return errors


def validate_forgot_password_form(email):
    """Validate forgot password form"""
    if not email:
        return False, "Email is required"
    
    if '@' not in email or '.' not in email:
        return False, "Invalid email format"
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return False, "Email not found"
    
    if user.is_banned:
        return False, "Account is banned"
    
    return True, user


def validate_reset_password_form(password, confirm_password):
    """Validate reset password form"""
    errors = []
    
    if not password:
        errors.append("Password is required")
    elif len(password) < 6:
        errors.append("Password must be at least 6 characters")
    
    if password != confirm_password:
        errors.append("Passwords do not match")
    
    return errors


def validate_credit_form(amount):
    """Validate credit addition form"""
    errors = []
    
    if not amount:
        errors.append("Amount is required")
    elif not amount.isdigit():
        errors.append("Amount must be a number")
    else:
        amount_int = int(amount)
        if amount_int < 1:
            errors.append("Amount must be at least 1")
        elif amount_int > 100:
            errors.append("Amount cannot exceed 100")
    
    return errors


def validate_license_form(license_type, duration_days=None):
    """Validate license activation form"""
    valid_types = ['Fair', 'Good', 'Excellent', 'Trial', '12hr', '24hr', '2day', '3day', '7day', 'Custom']
    
    if not license_type:
        return False, "License type is required"
    
    if license_type not in valid_types:
        return False, "Invalid license type"
    
    if duration_days:
        try:
            days = int(duration_days)
            if days <= 0:
                return False, "Duration must be positive"
        except ValueError:
            return False, "Duration must be a number"
    
    return True, None


# ==================== EXPORT ALL ====================

__all__ = [
    'LoginForm',
    'RegistrationForm',
    'handle_login_form',
    'handle_registration_form',
    'handle_password_change',
    'validate_forgot_password_form',
    'validate_reset_password_form',
    'validate_credit_form',
    'validate_license_form'
]