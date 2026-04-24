from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from database import db, User, Device, SystemLog, CreditTransaction, DeviceHistory
from datetime import datetime
import traceback

user_bp = Blueprint('user', __name__, url_prefix='/api/user')

# ==================== USER PROFILE ====================

@user_bp.route('/profile', methods=['GET'])
@login_required
def get_profile():
    """Get current user's profile information"""
    try:
        user = current_user
        
        # Get device count
        device_count = Device.query.filter_by(user_id=user.id, is_active=True).count()
        
        return jsonify({
            'success': True,
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'admission_number': user.admission_number,
            'country': user.country or 'Unknown',  # ADDED: Country field
            'credits': user.credits or 0,
            'license_type': user.license_type or 'None',
            'license_status': user.license_status or 'inactive',
            'license_expiry': user.license_expiry_date.isoformat() if user.license_expiry_date else None,
            'license_key': user.license_key,
            'device_limit': user.device_limit or 2,
            'device_count': device_count,
            'is_banned': user.is_banned or False,
            'is_active': user.is_active,
            'is_reseller': user.is_reseller or False,
            'is_admin': user.is_admin or False,
            'commission_rate': user.commission_rate or 0,
            'total_commission': user.total_commission or 0,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'last_login': user.last_login.isoformat() if user.last_login else None
        }), 200
    except Exception as e:
        print(f"❌ Profile error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== CHANGE PASSWORD ====================

@user_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    try:
        data = request.get_json() or {}
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({'success': False, 'error': 'Current password and new password required'}), 400
        
        if len(new_password) < 6:
            return jsonify({'success': False, 'error': 'New password must be at least 6 characters'}), 400
        
        user = current_user
        
        if not user.check_password(current_password):
            return jsonify({'success': False, 'error': 'Current password is incorrect'}), 401
        
        user.set_password(new_password)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Password changed successfully'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"❌ Password change error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== USER DEVICES ====================

@user_bp.route('/devices', methods=['GET'])
@login_required
def get_user_devices():
    """Get current user's registered devices"""
    try:
        devices = Device.query.filter_by(user_id=current_user.id)\
            .order_by(Device.last_seen.desc()).all()
        
        # Count active devices
        active_devices = [d for d in devices if d.is_active]
        
        devices_data = []
        for device in devices:
            devices_data.append({
                'id': device.id,
                'device_name': device.device_name or 'Unknown Device',
                'hwid': device.hwid_hash[:16] + '...' if device.hwid_hash and len(device.hwid_hash) > 16 else (device.hwid_hash or ''),
                'full_hwid': device.hwid_hash,  # For admin/debug
                'is_active': device.is_active,
                'is_trusted': device.is_trusted or False,
                'first_seen': device.first_seen.isoformat() if device.first_seen else None,
                'last_seen': device.last_seen.isoformat() if device.last_seen else None,
                'created_at': device.created_at.isoformat() if device.created_at else None,
                'ip_address': device.ip_address
            })
        
        return jsonify({
            'success': True,
            'devices': devices_data,
            'active_device_count': len(active_devices),
            'device_count': len(devices_data),
            'device_limit': current_user.device_limit or 2,
            'remaining_slots': max(0, (current_user.device_limit or 2) - len(active_devices)),
            'limit_reached': len(active_devices) >= (current_user.device_limit or 2)
        }), 200
    except Exception as e:
        print(f"❌ Devices error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== DEVICE HISTORY ====================

@user_bp.route('/device-history', methods=['GET'])
@login_required
def get_device_history():
    """Get device history for current user"""
    try:
        limit = int(request.args.get('limit', 50))
        
        history = DeviceHistory.query.filter_by(user_id=current_user.id)\
            .order_by(DeviceHistory.created_at.desc())\
            .limit(limit).all()
        
        history_data = []
        for h in history:
            history_data.append({
                'id': h.id,
                'device_id': h.device_id,
                'device_name': h.device_name,
                'action': h.action,
                'reason': h.reason,
                'ip_address': h.ip_address,
                'created_at': h.created_at.isoformat() if h.created_at else None
            })
        
        return jsonify({
            'success': True,
            'history': history_data
        }), 200
    except Exception as e:
        print(f"❌ History error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== RESET COST ====================

@user_bp.route('/reset-cost', methods=['GET'])
@login_required
def get_reset_cost():
    """Get cost to reset devices"""
    try:
        user = current_user
        active_devices = Device.query.filter_by(user_id=user.id, is_active=True).count()
        cost_per_device = 2
        
        devices_list = []
        if active_devices > 0:
            devices = Device.query.filter_by(user_id=user.id, is_active=True).all()
            devices_list = [{
                'id': d.id,
                'name': d.device_name or 'Unknown',
                'hwid_preview': (d.hwid_hash[:16] + '...') if d.hwid_hash and len(d.hwid_hash) > 16 else (d.hwid_hash or 'Unknown')
            } for d in devices]
        
        return jsonify({
            'success': True,
            'cost_per_device': cost_per_device,
            'total_devices': active_devices,
            'total_cost_all': active_devices * cost_per_device,
            'user_credits': user.credits or 0,
            'can_reset_all': (user.credits or 0) >= (active_devices * cost_per_device),
            'can_reset_single': (user.credits or 0) >= cost_per_device and active_devices > 0,
            'devices': devices_list
        }), 200
    except Exception as e:
        print(f"❌ Reset cost error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== SELF RESET HWID ====================

@user_bp.route('/self-reset-hwid', methods=['POST'])
@login_required
def self_reset_hwid():
    """Reset user's own HWID (costs credits)"""
    try:
        data = request.get_json() or {}
        reset_type = data.get('reset_type', 'single')
        device_id = data.get('device_id')
        credit_cost = data.get('credit_cost', 2)
        
        user = current_user
        
        if reset_type == 'all':
            # Reset all devices
            devices = Device.query.filter_by(user_id=user.id, is_active=True).all()
            total_cost = len(devices) * credit_cost
            
            if len(devices) == 0:
                return jsonify({'success': False, 'error': 'No active devices to reset'}), 400
            
            if (user.credits or 0) < total_cost:
                return jsonify({'success': False, 'error': f'Insufficient credits. Need {total_cost}, have {user.credits or 0}'}), 400
            
            reset_devices = []
            for device in devices:
                device.is_active = False
                device.is_bound = False
                reset_devices.append({
                    'id': device.id,
                    'hwid': device.hwid_hash,
                    'device_name': device.device_name
                })
            
            # Deactivate sessions
            from database import UserSession
            UserSession.query.filter_by(user_id=user.id, is_active=True).update({'is_active': False})
            
            # Deduct credits
            user.credits = (user.credits or 0) - total_cost
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': f'Successfully reset {len(devices)} devices',
                'devices_reset': reset_devices,
                'credits_remaining': user.credits or 0,
                'devices_count': len(devices)
            }), 200
            
        elif reset_type == 'single':
            if not device_id:
                return jsonify({'success': False, 'error': 'Device ID required'}), 400
            
            device = Device.query.filter_by(id=device_id, user_id=user.id, is_active=True).first()
            if not device:
                return jsonify({'success': False, 'error': 'Device not found'}), 404
            
            if (user.credits or 0) < credit_cost:
                return jsonify({'success': False, 'error': f'Insufficient credits. Need {credit_cost}, have {user.credits or 0}'}), 400
            
            device_info = {
                'id': device.id,
                'hwid': device.hwid_hash,
                'device_name': device.device_name
            }
            
            device.is_active = False
            device.is_bound = False
            
            # Deactivate sessions
            from database import UserSession
            UserSession.query.filter_by(device_id=device.id, is_active=True).update({'is_active': False})
            
            user.credits = (user.credits or 0) - credit_cost
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Device reset successfully',
                'device': device_info,
                'credits_remaining': user.credits or 0
            }), 200
        
        return jsonify({'success': False, 'error': 'Invalid reset type'}), 400
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Self reset error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== DASHBOARD STATS (Optional - Added) ====================

@user_bp.route('/dashboard-stats', methods=['GET'])
@login_required
def dashboard_stats():
    """Get user dashboard statistics"""
    try:
        user = current_user
        
        # Count active devices
        active_devices = Device.query.filter_by(user_id=user.id, is_active=True).count()
        
        # Get recent logs
        recent_logs = DeviceHistory.query.filter_by(user_id=user.id)\
            .order_by(DeviceHistory.created_at.desc())\
            .limit(10).all()
        
        # Calculate days remaining
        days_remaining = None
        if user.license_expiry_date:
            days_remaining = (user.license_expiry_date - datetime.utcnow()).days
            if days_remaining < 0:
                days_remaining = 0
        
        # Check if license is trial/short-term
        is_trial = user.license_type in ['Trial', '12hr', '24hr', '2day', '3day', '7day']
        
        return jsonify({
            'success': True,
            'username': user.username,
            'email': user.email,
            'country': user.country or 'Unknown',
            'license_type': user.license_type,
            'license_expiry': user.license_expiry_date.isoformat() if user.license_expiry_date else None,
            'days_remaining': days_remaining,
            'credits': user.credits or 0,
            'device_limit': user.device_limit,
            'device_count': active_devices,
            'device_usage_percent': (active_devices / user.device_limit * 100) if user.device_limit > 0 else 0,
            'is_trial': is_trial,
            'limit_reached': active_devices >= user.device_limit,
            'recent_activity': [{
                'time': log.created_at.isoformat(),
                'action': log.action,
                'device': log.device_name
            } for log in recent_logs]
        }), 200
    except Exception as e:
        print(f"❌ Dashboard stats error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500