from flask import Blueprint, jsonify, request, current_app, render_template
from flask_login import login_required, current_user
from sqlalchemy import text, or_, and_, func
from datetime import datetime, timedelta
import secrets
import os
import hashlib
from database import db, User, Device, SystemLog, CreditTransaction, ResellerCommission, DeviceHistory, UserSession
from utils.decorators import admin_required
from utils.helpers import log_system
from werkzeug.security import generate_password_hash

# List of protected admin emails that cannot be modified/banned
PROTECTED_ADMINS = ['clintonmoipan34@gmail.com']

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')

# ==================== GLOBAL KILL SWITCH ====================
SERVER_ACTIVE = True
KILL_SWITCH_KEY = os.getenv('KILL_SWITCH_KEY', secrets.token_urlsafe(32))
KILL_SWITCH_REASON = "Server maintenance in progress"


@admin_bp.route('/kill-switch', methods=['POST'])
@login_required
@admin_required
def kill_switch():
    """Emergency kill switch - blocks all non-admin access"""
    global SERVER_ACTIVE, KILL_SWITCH_REASON
    
    data = request.get_json(silent=True) or {}
    provided_key = data.get('key')
    action = data.get('action', 'toggle')
    reason = data.get('reason', KILL_SWITCH_REASON)
    
    if provided_key != KILL_SWITCH_KEY:
        log_system(current_user.id, 'kill_switch_failed', 
                  f'Failed kill switch attempt with invalid key', request)
        return jsonify({'error': 'Invalid kill switch key'}), 403
    
    old_state = SERVER_ACTIVE
    KILL_SWITCH_REASON = reason
    
    if action == 'enable':
        SERVER_ACTIVE = True
        message = "Server re-enabled"
    elif action == 'disable':
        SERVER_ACTIVE = False
        message = "SERVER DISABLED - All non-admin access blocked"
    else:
        SERVER_ACTIVE = not SERVER_ACTIVE
        message = f"Server {'disabled' if not SERVER_ACTIVE else 'enabled'}"
    
    log_system(current_user.id, 'kill_switch', 
              f'Kill switch {action}: Server {"ACTIVE" if SERVER_ACTIVE else "DISABLED"}. Reason: {reason}', 
              request)
    
    return jsonify({
        'success': True,
        'server_active': SERVER_ACTIVE,
        'previous_state': old_state,
        'message': message,
        'reason': KILL_SWITCH_REASON
    })


@admin_bp.route('/kill-switch-status', methods=['GET'])
def kill_switch_status():
    """Public endpoint to check if server is active"""
    return jsonify({
        'server_active': SERVER_ACTIVE,
        'reason': KILL_SWITCH_REASON if not SERVER_ACTIVE else None
    })


# ==================== HELPER FUNCTIONS ====================

def get_device_limit_for_license(license_type, custom_limit=None):
    """
    Get device limit based on license type
    - If custom_limit is provided, use that (0 = unlimited)
    - Special licenses (Trial, Custom) can have unlimited devices
    """
    if custom_limit is not None:
        return custom_limit if custom_limit > 0 else 999999  # 0 means unlimited
    
    # Standard licenses with limits
    limits = {
        'Fair': 10,
        'Good': 25,
        'Excellent': 55,
        'Trial': 999999,      # Unlimited devices
        'Custom': 999999,     # Unlimited devices
        'None': 2,
        None: 2
    }
    return limits.get(license_type, 2)


# ==================== ADVANCED LICENSE MANAGEMENT ====================

@admin_bp.route('/assign-license', methods=['POST'])
@login_required
@admin_required
def assign_license():
    """
    Assign license with flexible duration and device limit
    - Supports hours, days, weeks, months
    - Can set custom device limit (0 = unlimited)
    """
    try:
        data = request.get_json() or {}
        
        email = data.get('email')
        license_type = data.get('license_type', 'Custom')
        duration_value = data.get('duration_value')
        duration_unit = data.get('duration_unit', 'days')  # hours, days, weeks, months
        custom_device_limit = data.get('device_limit', 0)  # 0 = unlimited
        license_key = data.get('license_key') or secrets.token_urlsafe(32)
        
        if not email:
            return jsonify({'error': 'Email required'}), 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Calculate expiry date
        expiry_date = None
        if duration_value and duration_value > 0:
            now = datetime.utcnow()
            if duration_unit == 'hours':
                expiry_date = now + timedelta(hours=duration_value)
            elif duration_unit == 'days':
                expiry_date = now + timedelta(days=duration_value)
            elif duration_unit == 'weeks':
                expiry_date = now + timedelta(weeks=duration_value)
            elif duration_unit == 'months':
                expiry_date = now + timedelta(days=duration_value * 30)
            else:
                expiry_date = now + timedelta(days=duration_value)
        else:
            # No duration = permanent license
            expiry_date = None
        
        # Set device limit
        if custom_device_limit == 0:
            device_limit = 999999  # Unlimited
        else:
            device_limit = custom_device_limit
        
        # Update user license
        user.license_type = license_type
        user.license_key = license_key
        user.license_status = 'active'
        user.license_expiry_date = expiry_date
        user.device_limit = device_limit
        
        db.session.commit()
        
        # Log the action
        duration_text = f"{duration_value} {duration_unit}" if duration_value else "permanent"
        limit_text = "Unlimited" if device_limit >= 999999 else f"{device_limit} devices"
        
        log_system(current_user.id, 'license_assigned',
                  f'Assigned {license_type} license to {email} - Duration: {duration_text}, Device Limit: {limit_text}', 
                  request)
        
        return jsonify({
            'success': True,
            'message': f'{license_type} license assigned to {email}',
            'license': {
                'type': license_type,
                'expires_at': expiry_date.isoformat() if expiry_date else None,
                'device_limit': 'Unlimited' if device_limit >= 999999 else device_limit,
                'license_key': license_key
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/extend-license', methods=['POST'])
@login_required
@admin_required
def extend_license():
    """
    Extend existing license by additional days/hours
    """
    try:
        data = request.get_json() or {}
        
        email = data.get('email')
        extra_value = data.get('extra_value')
        extra_unit = data.get('extra_unit', 'days')  # hours, days, weeks, months
        
        if not email or not extra_value:
            return jsonify({'error': 'Email and duration required'}), 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Calculate new expiry date
        now = datetime.utcnow()
        current_expiry = user.license_expiry_date or now
        
        # If license is expired, start from now
        if current_expiry < now:
            current_expiry = now
        
        # Add extra time
        if extra_unit == 'hours':
            new_expiry = current_expiry + timedelta(hours=extra_value)
        elif extra_unit == 'days':
            new_expiry = current_expiry + timedelta(days=extra_value)
        elif extra_unit == 'weeks':
            new_expiry = current_expiry + timedelta(weeks=extra_value)
        elif extra_unit == 'months':
            new_expiry = current_expiry + timedelta(days=extra_value * 30)
        else:
            new_expiry = current_expiry + timedelta(days=extra_value)
        
        user.license_expiry_date = new_expiry
        user.license_status = 'active'
        
        db.session.commit()
        
        log_system(current_user.id, 'license_extended',
                  f'Extended license for {email} by {extra_value} {extra_unit}. New expiry: {new_expiry}', 
                  request)
        
        return jsonify({
            'success': True,
            'message': f'License extended by {extra_value} {extra_unit}',
            'new_expiry': new_expiry.isoformat(),
            'days_remaining': (new_expiry - datetime.utcnow()).days
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/set-device-limit', methods=['POST'])
@login_required
@admin_required
def set_device_limit():
    """
    Set custom device limit for a user (0 = unlimited)
    """
    try:
        data = request.get_json() or {}
        
        email = data.get('email')
        device_limit = data.get('device_limit', 0)
        
        if not email:
            return jsonify({'error': 'Email required'}), 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Set device limit (0 = unlimited)
        if device_limit == 0:
            user.device_limit = 999999
            limit_text = "Unlimited"
        else:
            user.device_limit = device_limit
            limit_text = f"{device_limit} devices"
        
        db.session.commit()
        
        log_system(current_user.id, 'device_limit_set',
                  f'Set device limit for {email} to {limit_text}', request)
        
        return jsonify({
            'success': True,
            'message': f'Device limit set to {limit_text}',
            'device_limit': limit_text
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ==================== SIMPLE CREDIT MANAGEMENT ====================

@admin_bp.route('/add-credits', methods=['POST'])
@login_required
@admin_required
def add_credits():
    """
    Add credits to a user (1-100 credits only)
    Simple and straightforward
    """
    try:
        data = request.get_json() or {}
        
        email = data.get('email')
        admission = data.get('admission')
        amount = data.get('amount')
        reason = data.get('reason', 'Admin credit addition')
        
        # Validate amount (1-100 only)
        if not amount:
            return jsonify({'error': 'Amount required'}), 400
        
        try:
            amount = int(amount)
        except ValueError:
            return jsonify({'error': 'Amount must be a number'}), 400
        
        if amount < 1 or amount > 100:
            return jsonify({'error': 'Amount must be between 1 and 100'}), 400
        
        # Find user
        user = None
        if email:
            user = User.query.filter_by(email=email).first()
        elif admission:
            try:
                admission_int = int(admission)
                user = User.query.filter_by(admission_number=admission_int).first()
            except ValueError:
                return jsonify({'error': 'Invalid admission number'}), 400
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Add credits
        old_balance = user.credits or 0
        user.credits = old_balance + amount
        
        # Create transaction record
        transaction = CreditTransaction(
            user_id=user.id,
            amount=amount,
            transaction_type='admin_add',
            description=reason,
            created_by=current_user.id
        )
        db.session.add(transaction)
        db.session.commit()
        
        log_system(current_user.id, 'credit_added',
                  f'Added {amount} credits to {user.email}. Old: {old_balance}, New: {user.credits}', 
                  request)
        
        return jsonify({
            'success': True,
            'message': f'Added {amount} credits to {user.username}',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            },
            'old_balance': old_balance,
            'new_balance': user.credits
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ==================== USER MANAGEMENT ====================

@admin_bp.route('/users', methods=['GET'])
@login_required
@admin_required
def get_users():
    """Get all users with filtering"""
    try:
        filter_type = request.args.get('filter', 'all')
        search = request.args.get('search', '').lower()
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        
        query = User.query
        
        # Apply filters
        if filter_type == 'regular':
            query = query.filter_by(is_admin=False, is_reseller=False)
        elif filter_type == 'resellers':
            query = query.filter_by(is_reseller=True)
        elif filter_type == 'admins':
            query = query.filter_by(is_admin=True)
        elif filter_type == 'banned':
            query = query.filter_by(is_banned=True)
        
        # Apply search
        if search:
            query = query.filter(
                or_(
                    User.username.ilike(f'%{search}%'),
                    User.email.ilike(f'%{search}%'),
                    func.cast(User.admission_number, db.String).ilike(f'%{search}%')
                )
            )
        
        total = query.count()
        users = query.order_by(User.id).offset((page - 1) * limit).limit(limit).all()
        
        users_data = []
        for user in users:
            device_count = Device.query.filter_by(user_id=user.id, is_active=True).count()
            users_data.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'admission_number': user.admission_number,
                'license_type': user.license_type,
                'license_status': user.license_status,
                'credits': user.credits or 0,
                'is_admin': user.is_admin,
                'is_reseller': user.is_reseller,
                'is_banned': user.is_banned,
                'device_count': device_count,
                'device_limit': 'Unlimited' if user.device_limit >= 999999 else user.device_limit,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'protected': user.email in PROTECTED_ADMINS
            })
        
        return jsonify({
            'success': True,
            'users': users_data,
            'total': total,
            'page': page,
            'pages': (total + limit - 1) // limit
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/user-details/<int:user_id>', methods=['GET'])
@login_required
@admin_required
def user_details(user_id):
    """Get detailed user information"""
    try:
        user = User.query.get_or_404(user_id)
        
        device_count = Device.query.filter_by(user_id=user.id, is_active=True).count()
        total_devices = Device.query.filter_by(user_id=user.id).count()
        
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'admission_number': user.admission_number,
                'license_type': user.license_type,
                'license_status': user.license_status,
                'license_expiry': user.license_expiry_date.isoformat() if user.license_expiry_date else None,
                'credits': user.credits or 0,
                'is_admin': user.is_admin,
                'is_reseller': user.is_reseller,
                'is_banned': user.is_banned,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'device_count': device_count,
                'total_devices': total_devices,
                'device_limit': 'Unlimited' if user.device_limit >= 999999 else user.device_limit,
                'protected': user.email in PROTECTED_ADMINS
            }
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== USER DEVICES ====================

@admin_bp.route('/user-devices/<int:user_id>', methods=['GET'])
@login_required
@admin_required
def get_user_devices(user_id):
    """Get all devices for a specific user"""
    try:
        devices = Device.query.filter_by(user_id=user_id)\
            .order_by(Device.last_seen.desc())\
            .all()
        
        devices_data = []
        for device in devices:
            devices_data.append({
                'id': device.id,
                'device_name': device.device_name,
                'hwid': device.hwid_hash[:16] + '...' if device.hwid_hash else 'Unknown',
                'full_hwid': device.hwid_hash,
                'is_active': device.is_active,
                'is_bound': device.is_bound,
                'first_seen': device.first_seen.isoformat() if device.first_seen else None,
                'last_seen': device.last_seen.isoformat() if device.last_seen else None,
                'created_at': device.created_at.isoformat() if device.created_at else None,
                'ip_address': device.ip_address
            })
        
        return jsonify({
            'success': True,
            'devices': devices_data,
            'total': len(devices_data)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/reset-device/<int:device_id>', methods=['POST'])
@login_required
@admin_required
def admin_reset_device(device_id):
    """Admin reset a specific device (free)"""
    try:
        device = Device.query.get_or_404(device_id)
        user = User.query.get(device.user_id)
        
        # Deactivate device
        device.is_active = False
        device.is_bound = False
        
        # Deactivate sessions
        UserSession.query.filter_by(device_id=device.id, is_active=True).update({'is_active': False})
        
        # Log the reset
        DeviceHistory.log_action(
            user_id=device.user_id,
            action='admin_reset',
            device=device,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            reason=f'Admin reset by {current_user.username}',
            extra_data={'admin_id': current_user.id}
        )
        
        db.session.commit()
        
        log_system(current_user.id, 'device_reset_admin',
                  f'Reset device {device.device_name} for user {user.email}', request)
        
        return jsonify({
            'success': True,
            'message': f'Device reset successfully',
            'device_id': device.id,
            'device_name': device.device_name
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/reset-all-devices/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_reset_all_devices(user_id):
    """Admin reset all devices for a user (free)"""
    try:
        user = User.query.get_or_404(user_id)
        
        devices = Device.query.filter_by(user_id=user.id, is_active=True).all()
        reset_count = len(devices)
        
        for device in devices:
            device.is_active = False
            device.is_bound = False
            
            DeviceHistory.log_action(
                user_id=user.id,
                action='admin_reset_all',
                device=device,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                reason=f'Admin reset all devices by {current_user.username}',
                extra_data={'admin_id': current_user.id}
            )
        
        # Deactivate all sessions
        UserSession.query.filter_by(user_id=user.id, is_active=True).update({'is_active': False})
        
        db.session.commit()
        
        log_system(current_user.id, 'devices_reset_admin',
                  f'Reset all {reset_count} devices for user {user.email}', request)
        
        return jsonify({
            'success': True,
            'message': f'Reset {reset_count} devices for {user.username}',
            'devices_reset': reset_count
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ==================== BAN/UNBAN USER ====================

@admin_bp.route('/ban-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def ban_user(user_id):
    """Ban or unban a user"""
    try:
        data = request.get_json() or {}
        ban_status = data.get('ban', True)
        
        user = User.query.get_or_404(user_id)
        
        # Protect main admins
        if user.email in PROTECTED_ADMINS:
            return jsonify({'error': 'Cannot ban protected admin account'}), 403
        
        user.is_banned = ban_status
        db.session.commit()
        
        log_system(current_user.id, 'user_banned' if ban_status else 'user_unbanned',
                  f'User {user.email} {"banned" if ban_status else "unbanned"}', request)
        
        return jsonify({
            'success': True,
            'message': f'User {"banned" if ban_status else "unbanned"} successfully',
            'is_banned': user.is_banned
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ==================== RESELLER MANAGEMENT ====================

@admin_bp.route('/make-reseller/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def make_reseller(user_id):
    """Make an existing user a reseller"""
    try:
        data = request.get_json() or {}
        commission_rate = data.get('commission_rate', 15)
        
        user = User.query.get_or_404(user_id)
        
        if user.is_admin:
            return jsonify({'error': 'Cannot make admin a reseller'}), 400
        
        if user.email in PROTECTED_ADMINS:
            return jsonify({'error': 'Cannot modify protected admin account'}), 403
        
        user.is_reseller = True
        user.commission_rate = commission_rate
        
        db.session.commit()
        
        log_system(current_user.id, 'user_made_reseller',
                  f'User {user.email} made reseller with {commission_rate}% commission', request)
        
        return jsonify({
            'success': True,
            'message': 'User is now a reseller'
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/remove-reseller/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def remove_reseller(user_id):
    """Remove reseller status from a user"""
    try:
        user = User.query.get_or_404(user_id)
        
        if not user.is_reseller:
            return jsonify({'error': 'User is not a reseller'}), 400
        
        if user.email in PROTECTED_ADMINS:
            return jsonify({'error': 'Cannot modify protected admin account'}), 403
        
        user.is_reseller = False
        user.commission_rate = 0
        
        db.session.commit()
        
        log_system(current_user.id, 'reseller_removed',
                  f'Reseller status removed from {user.email}', request)
        
        return jsonify({
            'success': True,
            'message': 'Reseller status removed'
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ==================== PASSWORD RESET (ADMIN) ====================

@admin_bp.route('/reset-password/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def reset_password(user_id):
    """Reset user password (admin only)"""
    try:
        user = User.query.get_or_404(user_id)
        
        # Protect main admins
        if user.email in PROTECTED_ADMINS and user.id != current_user.id:
            return jsonify({'error': 'Cannot reset protected admin password'}), 403
        
        new_password = secrets.token_urlsafe(8)
        user.set_password(new_password)
        user.reset_token = None
        user.reset_token_expiry = None
        
        db.session.commit()
        
        log_system(current_user.id, 'password_reset_admin',
                  f'Password reset for user {user.email}', request)
        
        return jsonify({
            'success': True,
            'message': 'Password reset successfully',
            'new_password': new_password,
            'user_id': user.id,
            'username': user.username
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ==================== STATISTICS ====================

@admin_bp.route('/stats', methods=['GET'])
@login_required
@admin_required
def get_stats():
    """Get system statistics"""
    try:
        total_users = User.query.count()
        active_users = User.query.filter_by(is_banned=False).count()
        banned_users = User.query.filter_by(is_banned=True).count()
        
        total_devices = Device.query.count()
        active_devices = Device.query.filter_by(is_active=True).count()
        
        total_credits = db.session.query(func.sum(User.credits)).scalar() or 0
        
        # License distribution
        license_dist = {}
        for lt in ['Fair', 'Good', 'Excellent', 'Custom', 'Trial', 'None']:
            count = User.query.filter_by(license_type=lt).count()
            if count > 0:
                license_dist[lt] = count
        
        # Recent signups (last 7 days)
        week_ago = datetime.utcnow() - timedelta(days=7)
        recent_signups = User.query.filter(User.created_at >= week_ago).count()
        
        return jsonify({
            'success': True,
            'users': {
                'total': total_users,
                'active': active_users,
                'banned': banned_users,
                'recent_signups': recent_signups
            },
            'devices': {
                'total': total_devices,
                'active': active_devices
            },
            'credits': {
                'total': total_credits
            },
            'license_distribution': license_dist
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== SYSTEM LOGS ====================

@admin_bp.route('/logs', methods=['GET'])
@login_required
@admin_required
def get_logs():
    """Get system logs"""
    try:
        limit = int(request.args.get('limit', 50))
        
        logs = SystemLog.query.order_by(SystemLog.created_at.desc()).limit(limit).all()
        
        logs_data = []
        for log in logs:
            user = User.query.get(log.user_id) if log.user_id else None
            logs_data.append({
                'id': log.id,
                'type': log.log_type,
                'message': log.message,
                'user_id': log.user_id,
                'username': user.username if user else 'System',
                'ip': log.ip_address,
                'created': log.created_at.isoformat()
            })
        
        return jsonify({
            'success': True,
            'logs': logs_data,
            'total': len(logs_data)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500