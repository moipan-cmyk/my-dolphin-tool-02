import hashlib
import hmac
import platform
import uuid
from datetime import datetime, timedelta
from flask import current_app
from database import db, Device, UserSession, DeviceHistory

class DeviceService:
    """Service for handling device registration and validation"""
    
    @staticmethod
    def generate_hwid(system_info):
        """
        Generate a unique hardware ID based on system information
        This should be implemented client-side, but here's the server validation
        """
        # In production, this would be generated client-side and sent to server
        # The server would validate the HWID format and signature
        components = [
            system_info.get('cpu_id', ''),
            system_info.get('motherboard_serial', ''),
            system_info.get('mac_address', ''),
            system_info.get('disk_serial', ''),
            system_info.get('os_uuid', '')
        ]
        
        # Create a unique HWID
        hwid_string = ':'.join(filter(None, components))
        if not hwid_string:
            # Fallback to generating based on available info
            hwid_string = str(uuid.uuid4())
        
        # Hash the HWID for storage
        return hashlib.sha256(hwid_string.encode()).hexdigest()
    
    @staticmethod
    def validate_hwid_format(hwid):
        """Validate HWID format"""
        # HWID should be a SHA256 hash (64 characters hex)
        if not hwid or len(hwid) != 64:
            return False
        try:
            int(hwid, 16)  # Check if it's valid hex
            return True
        except ValueError:
            return False
    
    @staticmethod
    def register_device(user_id, hwid, device_name=None, ip_address=None):
        """Register a new device with HWID"""
        user = User.query.get(user_id)
        if not user:
            return {'success': False, 'error': 'User not found'}
        
        # Check if device already registered to this user
        existing_device = Device.query.filter_by(
            user_id=user_id,
            hwid=hwid
        ).first()
        
        if existing_device:
            if existing_device.is_active:
                # Device already registered and active
                return {
                    'success': True,
                    'device': existing_device,
                    'message': 'Device already registered'
                }
            else:
                # Reactivate device
                existing_device.is_active = True
                existing_device.last_seen = datetime.utcnow()
                existing_device.ip_address = ip_address
                db.session.commit()
                
                DeviceHistory.log_action(
                    user_id=user_id,
                    device_id=hwid,
                    device_name=device_name,
                    hwid=hwid,
                    action='reactivate',
                    ip_address=ip_address
                )
                
                return {
                    'success': True,
                    'device': existing_device,
                    'message': 'Device reactivated'
                }
        
        # Check if HWID is already bound to another user
        other_device = Device.query.filter_by(hwid=hwid, is_bound=True).first()
        if other_device:
            return {
                'success': False, 
                'error': 'This hardware is already bound to another account',
                'code': 'HWID_ALREADY_BOUND'
            }
        
        # Check device limit
        if not user.can_register_device():
            return {
                'success': False,
                'error': f'Device limit reached ({user.device_limit} devices)',
                'code': 'DEVICE_LIMIT_REACHED'
            }
        
        # Register new device
        device = Device(
            user_id=user_id,
            device_id=hwid[:50],  # Truncate for storage
            device_name=device_name or f"Device-{hwid[:8]}",
            hwid=hwid,
            ip_address=ip_address,
            is_active=True,
            is_bound=True
        )
        
        db.session.add(device)
        db.session.commit()
        
        # Log the registration
        DeviceHistory.log_action(
            user_id=user_id,
            device_id=hwid,
            device_name=device_name,
            hwid=hwid,
            action='register',
            ip_address=ip_address
        )
        
        return {
            'success': True,
            'device': device,
            'message': 'Device registered successfully',
            'devices_remaining': user.device_limit - user.get_active_devices_count()
        }
    
    @staticmethod
    def create_session(user_id, hwid, ip_address=None):
        """Create a session for a device"""
        # Find the device
        device = Device.query.filter_by(
            user_id=user_id,
            hwid=hwid,
            is_active=True
        ).first()
        
        if not device:
            return {'success': False, 'error': 'Device not found or inactive'}
        
        # Check for existing active sessions
        existing_session = UserSession.query.filter_by(
            user_id=user_id,
            device_id=device.id,
            is_active=True
        ).filter(UserSession.expires_at > datetime.utcnow()).first()
        
        if existing_session:
            # Refresh existing session
            existing_session.refresh()
            return {
                'success': True,
                'session': existing_session,
                'message': 'Session refreshed'
            }
        
        # Deactivate any expired sessions for this device
        UserSession.query.filter_by(
            user_id=user_id,
            device_id=device.id,
            is_active=True
        ).filter(UserSession.expires_at <= datetime.utcnow()).update({'is_active': False})
        
        # Create new session
        session = device.create_session(expires_in_hours=12)
        
        # Update device last seen
        device.last_seen = datetime.utcnow()
        device.ip_address = ip_address
        db.session.commit()
        
        return {
            'success': True,
            'session': session,
            'message': 'Session created successfully'
        }
    
    @staticmethod
    def validate_session(session_token, hwid=None):
        """Validate a session token"""
        session = UserSession.query.filter_by(
            session_token=session_token,
            is_active=True
        ).first()
        
        if not session or not session.is_valid():
            return {'success': False, 'error': 'Invalid or expired session'}
        
        # If HWID provided, validate it matches
        if hwid:
            device = Device.query.get(session.device_id)
            if not device or device.hwid != hwid:
                return {'success': False, 'error': 'Session does not match device'}
        
        # Update last activity
        session.last_activity = datetime.utcnow()
        db.session.commit()
        
        return {
            'success': True,
            'session': session,
            'user_id': session.user_id
        }
    
    @staticmethod
    def change_pc(user_id, old_hwid, new_hwid, new_device_name=None, ip_address=None, credit_cost=2):
        """
        Allow user to change PC (transfer binding from old HWID to new HWID)
        This consumes a device slot and optionally costs credits
        """
        user = User.query.get(user_id)
        if not user:
            return {'success': False, 'error': 'User not found'}
        
        # Find old device
        old_device = Device.query.filter_by(
            user_id=user_id,
            hwid=old_hwid,
            is_active=True
        ).first()
        
        if not old_device:
            return {'success': False, 'error': 'Old device not found'}
        
        # Check if new HWID already exists
        existing_new = Device.query.filter_by(hwid=new_hwid).first()
        if existing_new:
            if existing_new.user_id == user_id:
                # Device already registered to this user
                return {'success': False, 'error': 'New device already registered to your account'}
            else:
                # HWID bound to another user
                return {
                    'success': False,
                    'error': 'This hardware is already bound to another account',
                    'code': 'HWID_ALREADY_BOUND'
                }
        
        # Check credit cost if applicable
        if credit_cost > 0 and user.credits < credit_cost:
            return {
                'success': False,
                'error': f'Insufficient credits. Need {credit_cost}, have {user.credits}',
                'code': 'INSUFFICIENT_CREDITS'
            }
        
        # Deactivate old device
        old_device.is_active = False
        old_device.is_bound = False
        
        # Deduct credits if cost > 0
        if credit_cost > 0:
            user.credits -= credit_cost
        
        # Create new device
        new_device = Device(
            user_id=user_id,
            device_id=new_hwid[:50],
            device_name=new_device_name or f"Device-{new_hwid[:8]}",
            hwid=new_hwid,
            ip_address=ip_address,
            is_active=True,
            is_bound=True
        )
        
        db.session.add(new_device)
        
        # Log the PC change
        DeviceHistory.log_action(
            user_id=user_id,
            device_id=new_hwid,
            device_name=new_device_name,
            hwid=new_hwid,
            action='change_pc',
            ip_address=ip_address
        )
        
        DeviceHistory.log_action(
            user_id=user_id,
            device_id=old_hwid,
            device_name=old_device.device_name,
            hwid=old_hwid,
            action='deactivated_change_pc',
            ip_address=ip_address
        )
        
        db.session.commit()
        
        # Create new session for the new device
        session = new_device.create_session()
        
        return {
            'success': True,
            'message': 'PC changed successfully',
            'new_device': new_device,
            'session': session,
            'credits_remaining': user.credits,
            'devices_remaining': user.device_limit - user.get_active_devices_count()
        }
    
    @staticmethod
    def reset_device_bindings(user_id, credit_cost=2):
        """Reset all device bindings for a user"""
        user = User.query.get(user_id)
        if not user:
            return {'success': False, 'error': 'User not found'}
        
        if user.credits < credit_cost:
            return {
                'success': False,
                'error': f'Insufficient credits. Need {credit_cost}, have {user.credits}',
                'code': 'INSUFFICIENT_CREDITS'
            }
        
        # Get all active devices
        devices = Device.query.filter_by(user_id=user_id, is_active=True).all()
        
        # Deactivate all devices
        for device in devices:
            device.is_active = False
            device.is_bound = False
            
            # Log the reset
            DeviceHistory.log_action(
                user_id=user_id,
                device_id=device.hwid,
                device_name=device.device_name,
                hwid=device.hwid,
                action='reset_bindings',
                ip_address=None
            )
        
        # Deduct credits
        user.credits -= credit_cost
        
        # Deactivate all sessions
        UserSession.query.filter_by(
            user_id=user_id,
            is_active=True
        ).update({'is_active': False})
        
        db.session.commit()
        
        return {
            'success': True,
            'message': f'All device bindings reset successfully. {credit_cost} credits deducted.',
            'credits_remaining': user.credits
        }