# license.py
"""
License management module for DOLPHIN BYPASS TOOL
Handles license types, validation, and assignment
"""

from datetime import datetime, timedelta
from flask import current_app
from database import db, User, SystemLog, LicenseTransaction

class LicenseManager:
    """Manages all license operations"""
    
    LICENSE_TYPES = {
        'Fair': {
            'days': 90,
            'duration_text': '3 Months',
            'price_key': 'LICENSE_PRICE_FAIR'
        },
        'Good': {
            'days': 180,
            'duration_text': '6 Months',
            'price_key': 'LICENSE_PRICE_GOOD'
        },
        'Excellent': {
            'days': 365,
            'duration_text': '12 Months',
            'price_key': 'LICENSE_PRICE_EXCELLENT'
        }
    }
    
    @classmethod
    def get_license_days(cls, license_type):
        """Get number of days for license type"""
        return cls.LICENSE_TYPES.get(license_type, {}).get('days', 0)
    
    @classmethod
    def get_license_duration_text(cls, license_type):
        """Get human-readable duration"""
        return cls.LICENSE_TYPES.get(license_type, {}).get('duration_text', 'No License')
    
    @classmethod
    def get_license_price(cls, license_type):
        """Get price for license type from config"""
        config_key = cls.LICENSE_TYPES.get(license_type, {}).get('price_key')
        if config_key:
            from flask import current_app
            return current_app.config.get(config_key, 0)
        return 0
    
    @classmethod
    def assign_license(cls, user, license_type, admin_user=None, transaction_id=None):
        """
        Assign a license to a user
        
        Args:
            user: User object
            license_type: 'Fair', 'Good', 'Excellent'
            admin_user: User who assigned (for logging)
            transaction_id: Optional payment transaction ID
        
        Returns:
            dict: Result with status and message
        """
        if license_type not in cls.LICENSE_TYPES:
            return {'success': False, 'error': 'Invalid license type'}
        
        days = cls.get_license_days(license_type)
        
        # Update user
        user.license_type = license_type
        user.license_status = 'active'
        user.license_expiry_date = datetime.utcnow() + timedelta(days=days)
        
        # Generate license key if not exists
        if not user.license_key:
            import secrets
            user.license_key = secrets.token_urlsafe(32)
        
        db.session.commit()
        
        # Create transaction record
        if transaction_id:
            transaction = LicenseTransaction(
                user_id=user.id,
                license_type=license_type,
                amount=cls.get_license_price(license_type),
                duration_days=days,
                transaction_id=transaction_id,
                payment_method='admin' if admin_user else 'system',
                status='completed',
                license_start=datetime.utcnow(),
                license_end=user.license_expiry_date
            )
            db.session.add(transaction)
            db.session.commit()
        
        # Log the action
        log_message = f"License {license_type} assigned to user {user.id}"
        if admin_user:
            log_message += f" by admin {admin_user.id}"
        
        log = SystemLog(
            user_id=user.id,
            log_type='license_assigned',
            message=log_message,
            ip_address=None
        )
        db.session.add(log)
        db.session.commit()
        
        return {
            'success': True,
            'message': f'{license_type} license assigned for {days} days',
            'license_key': user.license_key,
            'expiry': user.license_expiry_date.isoformat()
        }
    
    @classmethod
    def renew_license(cls, user, license_type=None, additional_days=None):
        """
        Renew an existing license
        
        Args:
            user: User object
            license_type: New license type (or None to keep same)
            additional_days: Additional days (or None to use default)
        
        Returns:
            dict: Result with status and message
        """
        if license_type:
            days = cls.get_license_days(license_type)
            user.license_type = license_type
        else:
            days = additional_days or cls.get_license_days(user.license_type)
        
        # Extend from current expiry or from now
        if user.license_expiry_date and user.license_expiry_date > datetime.utcnow():
            user.license_expiry_date += timedelta(days=days)
        else:
            user.license_expiry_date = datetime.utcnow() + timedelta(days=days)
        
        user.license_status = 'active'
        db.session.commit()
        
        return {
            'success': True,
            'message': f'License renewed for {days} days',
            'new_expiry': user.license_expiry_date.isoformat()
        }
    
    @classmethod
    def check_license(cls, user):
        """
        Check if user has valid license
        
        Returns:
            tuple: (is_valid, message, details)
        """
        if user.is_banned:
            return False, "Account is banned", {'banned': True}
        
        if user.license_type == 'None':
            return False, "No license assigned", {'license_type': 'None'}
        
        if not user.license_expiry_date:
            return False, "License expiry date not set", {}
        
        if datetime.utcnow() > user.license_expiry_date:
            user.license_status = 'expired'
            db.session.commit()
            return False, "License expired", {
                'expiry': user.license_expiry_date.isoformat()
            }
        
        days_left = (user.license_expiry_date - datetime.utcnow()).days
        return True, "License valid", {
            'license_type': user.license_type,
            'days_left': days_left,
            'expiry': user.license_expiry_date.isoformat()
        }
    
    @classmethod
    def get_license_stats(cls):
        """Get license statistics for admin dashboard"""
        from database import User
        
        stats = {
            'total_users': User.query.count(),
            'by_type': {},
            'expiring_soon': 0,
            'expired': 0
        }
        
        for license_type in cls.LICENSE_TYPES.keys():
            count = User.query.filter_by(license_type=license_type).count()
            stats['by_type'][license_type] = count
        
        stats['by_type']['None'] = User.query.filter_by(license_type='None').count()
        
        # Expiring in next 7 days
        week_from_now = datetime.utcnow() + timedelta(days=7)
        stats['expiring_soon'] = User.query.filter(
            User.license_expiry_date <= week_from_now,
            User.license_expiry_date > datetime.utcnow(),
            User.license_type != 'None'
        ).count()
        
        # Expired
        stats['expired'] = User.query.filter(
            User.license_expiry_date <= datetime.utcnow(),
            User.license_type != 'None'
        ).count()
        
        return stats


# ==========================
# DECORATOR FOR ROUTES
# ==========================

def license_required(required_type=None):
    """
    Decorator to require valid license for routes
    
    Args:
        required_type: Minimum license type required (None, 'Fair', 'Good', 'Excellent')
    """
    from functools import wraps
    from flask import jsonify, current_user
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({'error': 'Authentication required'}), 401
            
            is_valid, message, details = LicenseManager.check_license(current_user)
            
            if not is_valid:
                return jsonify({
                    'error': 'License required',
                    'message': message,
                    'details': details
                }), 403
            
            # Check minimum license type if specified
            if required_type:
                type_order = {'None': 0, 'Fair': 1, 'Good': 2, 'Excellent': 3}
                if type_order.get(current_user.license_type, 0) < type_order.get(required_type, 0):
                    return jsonify({
                        'error': 'License upgrade required',
                        'message': f'{required_type} license or higher required',
                        'current': current_user.license_type
                    }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator