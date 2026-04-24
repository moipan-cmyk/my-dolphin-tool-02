from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from database import db, Device, UserSession, DeviceHistory
from services.device_service import DeviceService
from datetime import datetime, timedelta

device_bp = Blueprint('device', __name__, url_prefix='/api/device')

@device_bp.route('/register', methods=['POST'])
def register_device():
    """Register a new device with HWID"""
    data = request.get_json() or {}
    
    # Get authentication (either session token or user credentials)
    auth_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if auth_token:
        # Validate session token
        session_validation = DeviceService.validate_session(auth_token)
        if not session_validation['success']:
            return jsonify({'success': False, 'error': 'Invalid session'}), 401
        user_id = session_validation['user_id']
    else:
        # Fallback to user_id in request (for testing)
        user_id = data.get('user_id')
        if not user_id:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
    
    # Get required data
    hwid = data.get('hwid')
    if not hwid:
        return jsonify({'success': False, 'error': 'HWID required'}), 400
    
    # Validate HWID format
    if not DeviceService.validate_hwid_format(hwid):
        return jsonify({'success': False, 'error': 'Invalid HWID format'}), 400
    
    device_name = data.get('device_name')
    ip_address = request.remote_addr
    
    # Register device
    result = DeviceService.register_device(
        user_id=user_id,
        hwid=hwid,
        device_name=device_name,
        ip_address=ip_address
    )
    
    if not result['success']:
        return jsonify(result), 400
    
    # Create session for the device
    session_result = DeviceService.create_session(
        user_id=user_id,
        hwid=hwid,
        ip_address=ip_address
    )
    
    return jsonify({
        'success': True,
        'message': result['message'],
        'device': {
            'id': result['device'].id,
            'hwid': result['device'].hwid,
            'device_name': result['device'].device_name,
            'created_at': result['device'].created_at.isoformat()
        },
        'session': {
            'token': session_result['session'].session_token,
            'expires_at': session_result['session'].expires_at.isoformat()
        } if session_result['success'] else None,
        'devices_remaining': result.get('devices_remaining')
    }), 201 if result.get('message') == 'Device registered successfully' else 200

@device_bp.route('/validate', methods=['POST'])
def validate_device():
    """Validate device and create/refresh session"""
    data = request.get_json() or {}
    
    hwid = data.get('hwid')
    session_token = data.get('session_token')
    
    if not hwid:
        return jsonify({'success': False, 'error': 'HWID required'}), 400
    
    # If session token provided, validate it
    if session_token:
        validation = DeviceService.validate_session(session_token, hwid)
        if validation['success']:
            return jsonify({
                'success': True,
                'valid': True,
                'session_token': session_token,
                'expires_at': validation['session'].expires_at.isoformat()
            })
    
    # No valid session, try to find device and create new session
    device = Device.query.filter_by(hwid=hwid, is_active=True).first()
    if not device:
        return jsonify({
            'success': False,
            'valid': False,
            'error': 'Device not registered or inactive'
        }), 404
    
    # Check if device is bound to a user
    if not device.is_bound:
        return jsonify({
            'success': False,
            'valid': False,
            'error': 'Device not bound to any user'
        }), 403
    
    # Create new session
    session_result = DeviceService.create_session(
        user_id=device.user_id,
        hwid=hwid,
        ip_address=request.remote_addr
    )
    
    if not session_result['success']:
        return jsonify({'success': False, 'error': session_result['error']}), 500
    
    return jsonify({
        'success': True,
        'valid': True,
        'session_token': session_result['session'].session_token,
        'expires_at': session_result['session'].expires_at.isoformat(),
        'user_id': device.user_id
    })

@device_bp.route('/change-pc', methods=['POST'])
@login_required
def change_pc():
    """Allow user to change PC (transfer binding)"""
    data = request.get_json() or {}
    
    old_hwid = data.get('old_hwid')
    new_hwid = data.get('new_hwid')
    
    if not old_hwid or not new_hwid:
        return jsonify({'success': False, 'error': 'Old and new HWID required'}), 400
    
    # Validate new HWID format
    if not DeviceService.validate_hwid_format(new_hwid):
        return jsonify({'success': False, 'error': 'Invalid new HWID format'}), 400
    
    # Check if change is allowed (user has device limit remaining)
    user = current_user
    if user.get_active_devices_count() >= user.device_limit:
        return jsonify({
            'success': False,
            'error': 'Device limit reached. Reset bindings or remove devices first.',
            'code': 'DEVICE_LIMIT_REACHED'
        }), 400
    
    # Get credit cost from config or use default
    credit_cost = data.get('credit_cost', 2)
    
    result = DeviceService.change_pc(
        user_id=current_user.id,
        old_hwid=old_hwid,
        new_hwid=new_hwid,
        new_device_name=data.get('new_device_name'),
        ip_address=request.remote_addr,
        credit_cost=credit_cost
    )
    
    if not result['success']:
        return jsonify(result), 400
    
    return jsonify({
        'success': True,
        'message': result['message'],
        'new_device': {
            'id': result['new_device'].id,
            'hwid': result['new_device'].hwid,
            'device_name': result['new_device'].device_name
        },
        'session_token': result['session'].session_token,
        'session_expires': result['session'].expires_at.isoformat(),
        'credits_remaining': result['credits_remaining'],
        'devices_remaining': result['devices_remaining']
    })

@device_bp.route('/reset-bindings', methods=['POST'])
@login_required
def reset_bindings():
    """Reset all device bindings for the current user"""
    data = request.get_json() or {}
    
    # Get credit cost from config or use default
    credit_cost = data.get('credit_cost', 2)
    
    result = DeviceService.reset_device_bindings(
        user_id=current_user.id,
        credit_cost=credit_cost
    )
    
    if not result['success']:
        return jsonify(result), 400
    
    return jsonify(result)

@device_bp.route('/list', methods=['GET'])
@login_required
def list_devices():
    """List all devices for the current user"""
    devices = Device.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).order_by(Device.last_seen.desc()).all()
    
    return jsonify({
        'success': True,
        'device_count': len(devices),
        'device_limit': current_user.device_limit,
        'remaining': current_user.device_limit - len(devices),
        'devices': [{
            'id': d.id,
            'hwid': d.hwid,
            'device_name': d.device_name,
            'last_seen': d.last_seen.isoformat() if d.last_seen else None,
            'created_at': d.created_at.isoformat(),
            'ip_address': d.ip_address,
            'is_bound': d.is_bound
        } for d in devices]
    })

@device_bp.route('/sessions', methods=['GET'])
@login_required
def list_sessions():
    """List all active sessions for the current user"""
    sessions = UserSession.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).filter(UserSession.expires_at > datetime.utcnow()).all()
    
    return jsonify({
        'success': True,
        'session_count': len(sessions),
        'sessions': [{
            'id': s.id,
            'device_id': s.device_id,
            'created_at': s.created_at.isoformat(),
            'expires_at': s.expires_at.isoformat(),
            'last_activity': s.last_activity.isoformat(),
            'ip_address': s.ip_address
        } for s in sessions]
    })

@device_bp.route('/logout', methods=['POST'])
@login_required
def logout_device():
    """Logout from current session"""
    data = request.get_json() or {}
    session_token = data.get('session_token')
    
    if not session_token:
        return jsonify({'success': False, 'error': 'Session token required'}), 400
    
    session = UserSession.query.filter_by(
        session_token=session_token,
        user_id=current_user.id
    ).first()
    
    if session:
        session.is_active = False
        db.session.commit()
        return jsonify({'success': True, 'message': 'Logged out successfully'})
    
    return jsonify({'success': False, 'error': 'Session not found'}), 404

@device_bp.route('/logout-all', methods=['POST'])
@login_required
def logout_all_devices():
    """Logout from all devices"""
    UserSession.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).update({'is_active': False})
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Logged out from all devices'})

@device_bp.route('/history', methods=['GET'])
@login_required
def device_history():
    """Get device history for the current user"""
    limit = request.args.get('limit', 50, type=int)
    
    history = DeviceHistory.query.filter_by(
        user_id=current_user.id
    ).order_by(DeviceHistory.created_at.desc()).limit(limit).all()
    
    return jsonify({
        'success': True,
        'history': [{
            'id': h.id,
            'device_id': h.device_id,
            'device_name': h.device_name,
            'action': h.action,
            'ip_address': h.ip_address,
            'created_at': h.created_at.isoformat()
        } for h in history]
    })