from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from database import CreditTransaction, Device, db, User  # Import directly from database
from werkzeug.security import check_password_hash, generate_password_hash
from utils.helpers import log_system

license_bp = Blueprint('license', __name__, url_prefix='/api/user')

@license_bp.route('/credits', methods=['GET'])
@login_required
def user_credits_api():
    try:
        transactions = CreditTransaction.query.filter_by(user_id=current_user.id).order_by(CreditTransaction.created_at.desc()).limit(50).all()
        return jsonify({
            'credits': current_user.credits or 0,
            'transactions': [{
                'amount': t.amount,
                'type': t.transaction_type,
                'description': t.description,
                'created_at': t.created_at.isoformat()
            } for t in transactions]
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@license_bp.route('/profile', methods=['GET'])
@login_required
def user_profile_api():
    # Import Device at the top now, so no need for inline import
    device_count = Device.query.filter_by(user_id=current_user.id).count()
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'email': current_user.email,
        'admission_number': current_user.admission_number,
        'license_type': current_user.license_type or 'None',
        'license_status': current_user.license_status or 'inactive',
        'license_expiry': current_user.license_expiry_date.isoformat() if current_user.license_expiry_date else None,
        'license_key': current_user.license_key,
        'credits': current_user.credits or 0,
        'commission_rate': getattr(current_user, 'commission_rate', 0) or 0,
        'total_commission': getattr(current_user, 'total_commission', 0) or 0,
        'device_limit': current_user.device_limit or 2,
        'device_count': device_count,
        'is_banned': current_user.is_banned,
        'is_active': current_user.is_active,
        'created_at': current_user.created_at.isoformat() if current_user.created_at else None,
        'is_admin': getattr(current_user, 'is_admin', False),
        'is_reseller': getattr(current_user, 'is_reseller', False)
    }), 200

@license_bp.route('/change-password', methods=['POST'])
@login_required
def change_password_api():
    data = request.get_json(silent=True) or {}
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({'error': 'Current password and new password are required'}), 400
    
    if len(new_password) < 6:
        return jsonify({'error': 'New password must be at least 6 characters long'}), 400
    
    if not check_password_hash(current_user.password_hash, current_password):
        return jsonify({'error': 'Current password is incorrect'}), 400
    
    try:
        current_user.set_password(new_password)
        db.session.commit()
        log_system(current_user.id, 'password_changed', 'User changed password', request)
        return jsonify({'message': 'Password updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update password'}), 500