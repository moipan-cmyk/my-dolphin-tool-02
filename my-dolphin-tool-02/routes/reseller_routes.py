from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from datetime import datetime, timedelta
import secrets
from database import db, User  # Import User directly from database
from utils.decorators import reseller_required
from utils.helpers import log_system

reseller_bp = Blueprint('reseller', __name__, url_prefix='/api/reseller')

@reseller_bp.route('/activate-client', methods=['POST'])
@login_required
@reseller_required
def activate_client():
    data = request.get_json(silent=True) or {}
    name = data.get('name')
    email = data.get('email')
    phone = data.get('phone')
    license_type = data.get('license_type')
    payment_method = data.get('payment_method')
    payment_ref = data.get('payment_ref')
    credits_used = data.get('credits_used', 0)
    
    if not all([name, email, license_type, payment_method]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if license_type not in ['Fair', 'Good', 'Excellent']:
        return jsonify({'error': 'Invalid license type'}), 400
    
    try:
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'User with this email already exists'}), 409
        
        # Check if reseller has enough credits
        if credits_used > 0 and (current_user.credits or 0) < credits_used:
            return jsonify({'error': 'Insufficient credits'}), 403
        
        # Generate admission number
        last_user = User.query.order_by(User.admission_number.desc()).first()
        admission_number = (last_user.admission_number + 1) if last_user else 1000
        
        # Set duration and pricing based on license type
        duration = {'Fair': 90, 'Good': 180, 'Excellent': 365}
        days = duration[license_type]
        price = {'Fair': 1500, 'Good': 2500, 'Excellent': 4000}[license_type]
        commission = int(price * (current_user.commission_rate or 15) / 100)
        
        # Create username from name
        username = name.lower().replace(' ', '_') + str(admission_number)[-4:]
        
        # Create new user
        user = User(
            username=username,
            email=email,
            admission_number=admission_number,
            license_type=license_type,
            license_status='active',
            license_expiry_date=datetime.utcnow() + timedelta(days=days),
            license_key=secrets.token_urlsafe(32),
            device_limit=2,
            credits=0,
            activated_by=current_user.id
        )
        user.set_password(secrets.token_urlsafe(8))  # Temporary password
        
        db.session.add(user)
        
        # Deduct credits from reseller if used
        if credits_used > 0:
            current_user.credits = (current_user.credits or 0) - credits_used
            current_user.total_sales = (current_user.total_sales or 0) + price
            current_user.total_commission = (current_user.total_commission or 0) + commission
        
        db.session.commit()
        
        # Log the activation
        log_system(current_user.id, 'reseller_activation', 
                  f'Reseller {current_user.email} activated {email} with {license_type} license', request)
        
        return jsonify({
            'success': True,
            'message': f'Client activated successfully with {license_type} license',
            'admission_number': admission_number,
            'username': username,
            'client': {
                'id': user.id,
                'name': name,
                'email': email,
                'admission_number': admission_number,
                'license_type': license_type,
                'expiry_date': user.license_expiry_date.isoformat()
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@reseller_bp.route('/clients', methods=['GET'])
@login_required
@reseller_required
def get_clients():
    filter_type = request.args.get('filter', 'all')
    search = request.args.get('search', '').lower()
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 10))
    offset = (page - 1) * limit
    
    try:
        query = User.query.filter_by(activated_by=current_user.id)
        
        # Apply filters
        if filter_type == 'active':
            query = query.filter_by(license_status='active')
        elif filter_type == 'expired':
            query = query.filter(User.license_expiry_date < datetime.utcnow())
        elif filter_type == 'this-month':
            month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            query = query.filter(User.created_at >= month_start)
        
        # Apply search
        if search:
            query = query.filter(
                (User.email.ilike(f'%{search}%')) |
                (User.username.ilike(f'%{search}%'))
            )
        
        total = query.count()
        clients = query.order_by(User.created_at.desc()).offset(offset).limit(limit).all()
        
        client_list = []
        for user in clients:
            days_left = 0
            if user.license_expiry_date:
                days_left = (user.license_expiry_date - datetime.utcnow()).days
            
            client_list.append({
                'id': user.id,
                'name': user.username,
                'email': user.email,
                'admission_number': user.admission_number,
                'license_type': user.license_type or 'None',
                'status': 'active' if user.license_status == 'active' and days_left > 0 else 'expired',
                'activated_date': user.created_at.strftime('%Y-%m-%d') if user.created_at else None,
                'expiry_date': user.license_expiry_date.strftime('%Y-%m-%d') if user.license_expiry_date else None,
                'days_left': max(0, days_left),
                'credits': user.credits or 0
            })
        
        # Calculate stats
        stats = {
            'total': total,
            'active': User.query.filter_by(activated_by=current_user.id, license_status='active').count(),
            'expired': User.query.filter_by(activated_by=current_user.id).filter(User.license_expiry_date < datetime.utcnow()).count(),
            'month': User.query.filter_by(activated_by=current_user.id).filter(User.created_at >= datetime.utcnow().replace(day=1)).count()
        }
        
        return jsonify({
            'clients': client_list,
            'total': total,
            'page': page,
            'pages': (total + limit - 1) // limit,
            'stats': stats
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@reseller_bp.route('/earnings', methods=['GET'])
@login_required
@reseller_required
def earnings():
    try:
        month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        month_clients = User.query.filter_by(activated_by=current_user.id).filter(User.created_at >= month_start).count()
        month_earnings = month_clients * 375  # Average commission
        
        return jsonify({
            'total_earnings': current_user.total_commission or 0,
            'month_earnings': month_earnings,
            'pending': 0,
            'withdrawn': 0,
            'credits': current_user.credits or 0,
            'commission_rate': current_user.commission_rate or 15,
            'total_sales': current_user.total_sales or 0
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@reseller_bp.route('/activation-history', methods=['GET'])
@login_required
@reseller_required
def activation_history():
    try:
        clients = User.query.filter_by(activated_by=current_user.id).order_by(User.created_at.desc()).limit(100).all()
        
        return jsonify({
            'history': [{
                'datetime': c.created_at.strftime('%Y-%m-%d %H:%M'),
                'client_name': c.username,
                'admission_number': c.admission_number,
                'license_type': c.license_type or 'None',
                'payment_method': 'N/A',
                'amount': 0,
                'commission': 0
            } for c in clients]
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500