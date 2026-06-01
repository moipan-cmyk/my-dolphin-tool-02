from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import hashlib
import json

db = SQLAlchemy()


# ==========================
# USER MODEL (UPDATED with device binding fields)
# ==========================

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    admission_number = db.Column(db.Integer, unique=True, nullable=False, index=True)
    
    country = db.Column(db.String(100), nullable=True, default='Unknown')
    license_key = db.Column(db.String(255), unique=True, nullable=True)
    license_type = db.Column(db.String(20), default='None', nullable=False)
    license_expiry_date = db.Column(db.DateTime, nullable=True)
    license_status = db.Column(db.String(20), default='inactive')
    device_limit = db.Column(db.Integer, default=2)
    total_devices_registered = db.Column(db.Integer, default=0)
    credits = db.Column(db.Integer, default=0)
    commission_rate = db.Column(db.Integer, default=15)
    total_sales = db.Column(db.Integer, default=0)
    total_commission = db.Column(db.Integer, default=0)
    activated_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    is_banned = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_reseller = db.Column(db.Boolean, default=False)
    
    activation_limit = db.Column(db.Integer, default=10)
    activations_used = db.Column(db.Integer, default=0)
    
    reset_token = db.Column(db.String(100), unique=True, nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    current_session_key = db.Column(db.String(128), nullable=True)
    last_session_key = db.Column(db.String(128), nullable=True)
    last_used_hwid_hash = db.Column(db.String(256), nullable=True)
    hwid_change_count = db.Column(db.Integer, default=0)
    suspended_until = db.Column(db.DateTime, nullable=True)
    failed_login_count = db.Column(db.Integer, default=0)
    
    # ========== NEW DEVICE BINDING FIELDS ==========
    bound_hwid_hash = db.Column(db.String(256), nullable=True, index=True)  # Stored HWID
    bound_pc_manufacturer = db.Column(db.String(200), nullable=True)
    bound_windows_version = db.Column(db.String(100), nullable=True)
    bound_hardware_fingerprint = db.Column(db.String(256), nullable=True, index=True)
    bound_system_info = db.Column(db.Text, nullable=True)  # JSON string
    bound_ip_address = db.Column(db.String(50), nullable=True)
    bound_at = db.Column(db.DateTime, nullable=True)
    last_verified_at = db.Column(db.DateTime, nullable=True)
    verification_failures = db.Column(db.Integer, default=0)
    is_verified_device = db.Column(db.Boolean, default=False)

    # Relationships
    activator = db.relationship('User', remote_side=[id], backref='activated_clients', foreign_keys=[activated_by])
    devices = db.relationship('Device', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    device_history = db.relationship('DeviceHistory', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    sessions = db.relationship('UserSession', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    command_usage = db.relationship('CommandUsage', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    login_attempts = db.relationship('LoginAttempt', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    __table_args__ = (
        db.CheckConstraint("license_type IN ('None', 'Fair', 'Good', 'Excellent', 'Trial', 'Custom', '12hr', '24hr', '2day', '3day', '7day')", name='check_license_type'),
        db.CheckConstraint("license_status IN ('inactive', 'active', 'expired', 'suspended')", name='check_license_status'),
        db.CheckConstraint("credits >= 0", name='check_credits_non_negative'),
        db.CheckConstraint("commission_rate BETWEEN 0 AND 100", name='check_commission_rate'),
        db.CheckConstraint("verification_failures >= 0", name='check_verification_failures'),
        db.Index('idx_user_bound_hwid', 'bound_hwid_hash'),
        db.Index('idx_user_bound_fingerprint', 'bound_hardware_fingerprint'),
        db.Index('idx_user_verified_device', 'is_verified_device'),
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_license(self, license_type='Fair', days_valid=None):
        self.license_key = secrets.token_urlsafe(32)
        self.license_type = license_type
        if days_valid is None:
            days_valid = {'Fair': 90, 'Good': 180, 'Excellent': 365}.get(license_type, 0)
        if days_valid > 0:
            self.license_expiry_date = datetime.utcnow() + timedelta(days=days_valid)
            self.license_status = 'active'
            self.update_device_limit()
        else:
            self.license_expiry_date = None
            self.license_status = 'inactive'
            self.device_limit = 2
        return self.license_key

    def update_device_limit(self):
        limits = {'Fair': 10, 'Good': 25, 'Excellent': 55, 'Trial': 1, 'Custom': 1, '12hr': 1, '24hr': 1, '2day': 1, '3day': 1, '7day': 1, 'None': 2}
        self.device_limit = limits.get(self.license_type, 2)

    def is_license_valid(self):
        if self.is_banned: return False
        if self.license_type == 'None': return False
        if not self.license_expiry_date: return False
        if datetime.utcnow() > self.license_expiry_date: 
            self.license_status = 'expired'
            return False
        return self.license_status == 'active'

    def can_register_device(self):
        return Device.query.filter_by(user_id=self.id, is_active=True).count() < self.device_limit

    def get_active_devices_count(self):
        return Device.query.filter_by(user_id=self.id, is_active=True).count()

    def get_active_sessions_count(self):
        return UserSession.query.filter_by(user_id=self.id, is_active=True).filter(UserSession.expires_at > datetime.utcnow()).count()

    def add_credits(self, amount, transaction_type='admin_add', description='', admin_id=None):
        self.credits = (self.credits or 0) + amount
        transaction = CreditTransaction(user_id=self.id, amount=amount, transaction_type=transaction_type, description=description, created_by=admin_id)
        db.session.add(transaction)
        return transaction

    def deduct_credits(self, amount, transaction_type='usage', description=''):
        if (self.credits or 0) < amount: 
            return False
        self.credits = (self.credits or 0) - amount
        transaction = CreditTransaction(user_id=self.id, amount=-amount, transaction_type=transaction_type, description=description)
        db.session.add(transaction)
        return True

    def generate_reset_token(self):
        self.reset_token = secrets.token_urlsafe(32)
        self.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
        return self.reset_token

    def verify_reset_token(self, token):
        return self.reset_token and self.reset_token == token and self.reset_token_expiry and datetime.utcnow() <= self.reset_token_expiry

    def clear_reset_token(self):
        self.reset_token = None
        self.reset_token_expiry = None

    # ========== NEW DEVICE BINDING METHODS ==========
    
    def bind_device(self, hwid_hash, pc_manufacturer, windows_version, hardware_fingerprint, system_info, ip_address):
        """Bind a device to this user account"""
        self.bound_hwid_hash = hwid_hash
        self.bound_pc_manufacturer = pc_manufacturer
        self.bound_windows_version = windows_version
        self.bound_hardware_fingerprint = hardware_fingerprint
        self.bound_system_info = json.dumps(system_info) if isinstance(system_info, dict) else system_info
        self.bound_ip_address = ip_address
        self.bound_at = datetime.utcnow()
        self.last_verified_at = datetime.utcnow()
        self.is_verified_device = True
        self.verification_failures = 0
        db.session.commit()
    
    def verify_device_match(self, hwid_hash, hardware_fingerprint=None):
        """Verify current device matches bound device"""
        if not self.bound_hwid_hash:
            return False, "Device not bound"
        
        if hwid_hash != self.bound_hwid_hash:
            self.verification_failures += 1
            db.session.commit()
            
            if self.verification_failures >= 3:
                self.suspended_until = datetime.utcnow() + timedelta(hours=24)
                db.session.commit()
                return False, f"Device mismatch! Account suspended for 24 hours. (Attempt {self.verification_failures}/3)"
            
            return False, f"HWID mismatch! Attempt {self.verification_failures}/3"
        
        # Optional: Verify hardware fingerprint as well
        if hardware_fingerprint and self.bound_hardware_fingerprint:
            if hardware_fingerprint != self.bound_hardware_fingerprint:
                self.verification_failures += 1
                db.session.commit()
                return False, f"Hardware fingerprint mismatch! Attempt {self.verification_failures}/3"
        
        # Update last verification timestamp
        self.last_verified_at = datetime.utcnow()
        db.session.commit()
        return True, "Device verified"
    
    def unbind_device(self):
        """Unbind device from user account (admin only)"""
        self.bound_hwid_hash = None
        self.bound_pc_manufacturer = None
        self.bound_windows_version = None
        self.bound_hardware_fingerprint = None
        self.bound_system_info = None
        self.bound_ip_address = None
        self.bound_at = None
        self.last_verified_at = None
        self.is_verified_device = False
        self.verification_failures = 0
        db.session.commit()
    
    def get_device_binding_info(self):
        """Get device binding information for display"""
        return {
            'is_bound': self.bound_hwid_hash is not None,
            'bound_at': self.bound_at.isoformat() if self.bound_at else None,
            'last_verified': self.last_verified_at.isoformat() if self.last_verified_at else None,
            'pc_manufacturer': self.bound_pc_manufacturer,
            'windows_version': self.bound_windows_version,
            'bound_ip': self.bound_ip_address,
            'verification_failures': self.verification_failures,
            'is_verified_device': self.is_verified_device,
            'hardware_fingerprint_preview': self.bound_hardware_fingerprint[:32] + '...' if self.bound_hardware_fingerprint else None
        }

    def __repr__(self):
        return f'<User {self.username} (Admission {self.admission_number}) from {self.country}>'


# ==========================
# DEVICE MODEL (UPDATED with binding fields)
# ==========================

class Device(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    hardware_id = db.Column(db.String(128), nullable=False)
    hwid_hash = db.Column(db.String(256), unique=True, nullable=False)
    device_name = db.Column(db.String(255), nullable=True)
    manufacturer = db.Column(db.String(100), nullable=True)
    model = db.Column(db.String(100), nullable=True)
    os_version = db.Column(db.String(100), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    is_bound = db.Column(db.Boolean, default=True)
    is_trusted = db.Column(db.Boolean, default=False)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # New fields for additional device info
    pc_manufacturer = db.Column(db.String(200), nullable=True)
    windows_version = db.Column(db.String(100), nullable=True)
    hardware_fingerprint = db.Column(db.String(256), nullable=True)
    
    sessions = db.relationship('UserSession', backref='device', lazy='dynamic', cascade='all, delete-orphan')
    history = db.relationship('DeviceHistory', backref='device_ref', lazy='dynamic', foreign_keys='DeviceHistory.device_id')
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'hwid_hash', name='unique_user_device'),
        db.Index('idx_devices_hwid_hash', 'hwid_hash'),
        db.Index('idx_devices_user_active', 'user_id', 'is_active'),
        db.Index('idx_devices_last_seen', 'last_seen'),
        db.Index('idx_devices_hardware_fingerprint', 'hardware_fingerprint'),
    )

    def generate_session_token(self):
        return hashlib.sha256(f"{self.user_id}:{self.hwid_hash}:{datetime.utcnow().timestamp()}:{secrets.token_hex(16)}".encode()).hexdigest()

    def create_session(self, expires_in_hours=12, ip_address=None, user_agent=None):
        UserSession.query.filter_by(device_id=self.id, is_active=True).update({'is_active': False})
        session = UserSession(
            user_id=self.user_id, 
            device_id=self.id, 
            session_token=self.generate_session_token(), 
            expires_at=datetime.utcnow() + timedelta(hours=expires_in_hours), 
            ip_address=ip_address or self.ip_address, 
            user_agent=user_agent
        )
        db.session.add(session)
        db.session.commit()
        return session

    def update_last_seen(self, ip_address=None):
        self.last_seen = datetime.utcnow()
        if ip_address: 
            self.ip_address = ip_address
        db.session.commit()

    def deactivate(self):
        self.is_active = False
        self.is_bound = False
        UserSession.query.filter_by(device_id=self.id, is_active=True).update({'is_active': False})
        db.session.commit()

    def __repr__(self):
        return f'<Device {self.hwid_hash[:16]}... for User {self.user_id}>'


# ==========================
# USER SESSION MODEL (UPDATED with binding fields)
# ==========================

class UserSession(db.Model):
    __tablename__ = 'user_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False)
    session_token = db.Column(db.String(256), unique=True, nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # New fields for session binding
    session_hwid_hash = db.Column(db.String(256), nullable=True)
    session_hardware_fingerprint = db.Column(db.String(256), nullable=True)
    session_pc_manufacturer = db.Column(db.String(200), nullable=True)
    session_windows_version = db.Column(db.String(100), nullable=True)
    
    __table_args__ = (
        db.Index('idx_sessions_user_active', 'user_id', 'is_active', 'expires_at'),
        db.Index('idx_sessions_token_expiry', 'session_token', 'expires_at'),
        db.Index('idx_sessions_hwid', 'session_hwid_hash'),
    )

    def is_valid(self): 
        return self.is_active and self.expires_at > datetime.utcnow()
    
    def refresh(self, hours=12): 
        self.expires_at = datetime.utcnow() + timedelta(hours=hours)
        self.last_activity = datetime.utcnow()
        db.session.commit()
        
    def invalidate(self): 
        self.is_active = False
        db.session.commit()

    @classmethod
    def cleanup_expired(cls):
        expired = cls.query.filter(cls.expires_at <= datetime.utcnow(), cls.is_active == True).update({'is_active': False})
        db.session.commit()
        return expired

    def __repr__(self): 
        return f'<UserSession {self.id} for User {self.user_id}>'


# ==========================
# DEVICE HISTORY MODEL (UPDATED)
# ==========================

class DeviceHistory(db.Model):
    __tablename__ = 'device_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='SET NULL'), nullable=True)
    hardware_id = db.Column(db.String(128), nullable=True)
    hwid_hash = db.Column(db.String(256), nullable=True)
    device_name = db.Column(db.String(255), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    reason = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    extra_data = db.Column(db.JSON, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        db.CheckConstraint("action IN ('register','unregister','reset','change_pc','login','logout','admin_deleted','reactivate','session_created','session_expired','admin_reset_all','admin_reset_single','admin_toggle_trust','reset_all','reset_single','device_bound','device_mismatch')", name='check_device_action'),
        db.Index('idx_device_history_user_date', 'user_id', 'created_at'),
        db.Index('idx_device_history_action', 'action')
    )

    @classmethod
    def log_action(cls, user_id, action, device=None, hwid_hash=None, device_name=None, ip_address=None, user_agent=None, reason=None, extra_data=None):
        history = cls(
            user_id=user_id, 
            device_id=device.id if device else None, 
            hardware_id=device.hardware_id if device else None, 
            hwid_hash=hwid_hash or (device.hwid_hash if device else None), 
            device_name=device_name or (device.device_name if device else None), 
            action=action, 
            reason=reason, 
            ip_address=ip_address, 
            user_agent=user_agent, 
            extra_data=extra_data
        )
        db.session.add(history)
        db.session.commit()
        return history

    def __repr__(self): 
        return f'<DeviceHistory {self.action} for User {self.user_id}>'


# ==========================
# SYSTEM LOGS MODEL
# ==========================

class SystemLog(db.Model):
    __tablename__ = 'system_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    log_type = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    user = db.relationship('User', backref=db.backref('logs', lazy=True))
    
    __table_args__ = (
        db.Index('idx_system_logs_user_created', 'user_id', 'created_at'),
    )
    
    def __repr__(self): 
        return f'<SystemLog {self.log_type}>'


# ==========================
# CREDIT TRANSACTION MODEL
# ==========================

class CreditTransaction(db.Model):
    __tablename__ = 'credit_transactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    transaction_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    user = db.relationship('User', foreign_keys=[user_id], backref='credit_transactions')
    creator = db.relationship('User', foreign_keys=[created_by])
    
    __table_args__ = (
        db.CheckConstraint("transaction_type IN ('admin_add','admin_deduct','purchase','usage','refund','commission','device_reset','pc_change','device_registration','credit_used','hwid_reset','otp_purchase','samsung_frp_order','reseller_gift')", name='check_transaction_type'),
        db.Index('idx_credit_transactions_user_date', 'user_id', 'created_at'),
    )
    
    def __repr__(self): 
        return f'<CreditTransaction {self.id}: {self.amount}>'


# ==========================
# RESELLER COMMISSION MODEL
# ==========================

class ResellerCommission(db.Model):
    __tablename__ = 'reseller_commissions'
    id = db.Column(db.Integer, primary_key=True)
    reseller_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    license_type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    commission = db.Column(db.Integer, nullable=False)
    commission_rate = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    reseller = db.relationship('User', foreign_keys=[reseller_id], backref='commissions_as_reseller')
    client = db.relationship('User', foreign_keys=[client_id], backref='commission_record')
    
    __table_args__ = (
        db.CheckConstraint("license_type IN ('Fair','Good','Excellent')", name='check_commission_license_type'),
        db.Index('idx_commissions_reseller_date', 'reseller_id', 'created_at')
    )
    
    def __repr__(self): 
        return f'<ResellerCommission {self.id}: {self.commission}>'


# ==========================
# LICENSE TRANSACTION MODEL
# ==========================

class LicenseTransaction(db.Model):
    __tablename__ = 'license_transactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    license_type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=True)
    duration_days = db.Column(db.Integer, nullable=False)
    transaction_id = db.Column(db.String(100), unique=True, nullable=True)
    payment_method = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(20), default='completed')
    purchased_at = db.Column(db.DateTime, default=datetime.utcnow)
    license_start = db.Column(db.DateTime, nullable=False)
    license_end = db.Column(db.DateTime, nullable=False)
    
    user = db.relationship('User', backref=db.backref('license_transactions', lazy=True))
    
    __table_args__ = (
        db.CheckConstraint("license_type IN ('Fair','Good','Excellent')", name='check_transaction_license_type'),
        db.CheckConstraint("status IN ('pending','completed','failed')", name='check_transaction_status'),
        db.Index('idx_license_transactions_user', 'user_id', 'purchased_at'),
        db.Index('idx_license_transactions_expiry', 'license_end')
    )
    
    def __repr__(self): 
        return f'<LicenseTransaction {self.license_type} for User {self.user_id}>'


# ==========================
# COMMAND USAGE MODEL
# ==========================

class CommandUsage(db.Model):
    __tablename__ = 'command_usage'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    command_date = db.Column(db.Date, nullable=False, default=datetime.utcnow().date)
    count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'command_date', name='unique_user_command_date'),
        db.Index('idx_command_usage_user_date', 'user_id', 'command_date'),
        db.Index('idx_command_usage_date', 'command_date'),
        db.CheckConstraint('count >= 0', name='check_command_count_non_negative'),
        db.CheckConstraint('count <= 100', name='check_command_count_max')
    )
    
    def __repr__(self): 
        return f'<CommandUsage User {self.user_id} Date {self.command_date}: {self.count}/100>'


# ==========================
# LOGIN ATTEMPT MODEL
# ==========================

class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'
    id = db.Column(db.Integer, primary_key=True)
    identifier = db.Column(db.String(255), nullable=False)
    attempt_type = db.Column(db.String(50), default='login')
    attempt_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=False)
    ip_address = db.Column(db.String(50), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    
    __table_args__ = (
        db.Index('idx_login_attempts_identifier_time', 'identifier', 'attempt_time'),
        db.Index('idx_login_attempts_ip_time', 'ip_address', 'attempt_time'),
        db.Index('idx_login_attempts_success_time', 'success', 'attempt_time'),
        db.CheckConstraint("attempt_type IN ('login','password_reset','api')", name='check_attempt_type')
    )
    
    def __repr__(self): 
        return f'<LoginAttempt {self.identifier} Success={self.success} at {self.attempt_time}>'


# ==========================
# STORED OTP MODEL
# ==========================

class StoredOTP(db.Model):
    """Pre-stored OTP codes that get consumed once when purchased by users"""
    __tablename__ = 'stored_otps'
    id = db.Column(db.Integer, primary_key=True)
    otp_code = db.Column(db.String(128), unique=True, nullable=False, index=True)
    otp_type = db.Column(db.String(50), nullable=False, index=True)
    otp_name = db.Column(db.String(100), nullable=False)
    credits_cost = db.Column(db.Integer, nullable=False)
    is_used = db.Column(db.Boolean, default=False, index=True)
    used_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    used_at = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    
    user = db.relationship('User', foreign_keys=[used_by], backref='used_otps')
    creator = db.relationship('User', foreign_keys=[created_by], backref='created_otps')
    
    __table_args__ = (
        db.Index('idx_otp_type_used', 'otp_type', 'is_used'),
        db.Index('idx_otp_used_by', 'used_by'),
        db.Index('idx_otp_used_at', 'used_at'),
        db.CheckConstraint("credits_cost >= 0", name='check_otp_cost_non_negative')
    )

    def to_dict(self, admin_view=False):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'otp_code': self.otp_code if (admin_view or not self.is_used) else self.otp_code[:4] + '****',
            'otp_type': self.otp_type,
            'otp_name': self.otp_name,
            'credits_cost': self.credits_cost,
            'is_used': self.is_used,
            'used_by': self.used_by,
            'used_by_username': self.user.username if self.user else None,
            'used_at': self.used_at.isoformat() if self.used_at else None,
            'notes': self.notes,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by_username': self.creator.username if self.creator else None,
        }

    def __repr__(self): 
        return f'<StoredOTP {self.id}: {self.otp_name} ({self.otp_type}) Used={self.is_used}>'


# ==========================
# SAMSUNG FRP ORDER MODEL
# ==========================

class SamsungOrder(db.Model):
    """Samsung FRP order model for tracking FRP bypass requests"""
    __tablename__ = 'samsung_orders'
    
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    imei = db.Column(db.String(20), nullable=False, index=True)
    android_version = db.Column(db.String(5), nullable=False)
    credits_cost = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='pending', index=True)
    order_data = db.Column(db.Text, nullable=True)
    admin_notes = db.Column(db.Text, nullable=True)
    processed_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    processed_at = db.Column(db.DateTime, nullable=True)
    result_code = db.Column(db.String(20), nullable=True)
    result_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', foreign_keys=[user_id], backref='samsung_orders')
    processor = db.relationship('User', foreign_keys=[processed_by], backref='processed_samsung_orders')
    
    __table_args__ = (
        db.CheckConstraint("android_version IN ('13', '14', '15', '16')", name='check_android_version'),
        db.CheckConstraint("status IN ('pending', 'processing', 'completed', 'failed', 'cancelled')", name='check_order_status'),
        db.CheckConstraint("credits_cost >= 0", name='check_credits_cost_non_negative'),
        db.Index('idx_samsung_orders_user_status', 'user_id', 'status'),
        db.Index('idx_samsung_orders_created', 'created_at'),
        db.Index('idx_samsung_orders_imei', 'imei'),
        db.Index('idx_samsung_orders_order_id', 'order_id'),
        db.Index('idx_samsung_orders_status', 'status'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'order_id': self.order_id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else None,
            'imei': self.imei,
            'android_version': self.android_version,
            'credits_cost': self.credits_cost,
            'status': self.status,
            'admin_notes': self.admin_notes,
            'result_code': self.result_code,
            'result_message': self.result_message,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'processed_at': self.processed_at.isoformat() if self.processed_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'processor_name': self.processor.username if self.processor else None,
        }

    def __repr__(self):
        return f'<SamsungOrder {self.order_id} - {self.status}>'


# ==========================
# SERVER STATUS MODEL
# ==========================

class ServerStatus(db.Model):
    __tablename__ = 'server_status'
    
    id = db.Column(db.Integer, primary_key=True)
    server_name = db.Column(db.String(50), unique=True, nullable=False, index=True)
    is_online = db.Column(db.Boolean, default=False)
    manual_override = db.Column(db.Boolean, default=False)
    last_check = db.Column(db.DateTime, default=datetime.utcnow)
    response_time = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        db.Index('idx_server_status_name', 'server_name'),
        db.Index('idx_server_status_online', 'is_online'),
    )
    
    def to_dict(self):
        return {
            'server_name': self.server_name,
            'is_online': self.is_online,
            'manual_override': self.manual_override,
            'last_check': self.last_check.isoformat() if self.last_check else None,
            'response_time': self.response_time,
            'error_message': self.error_message,
        }
    
    def __repr__(self):
        return f'<ServerStatus {self.server_name}: {"ONLINE" if self.is_online else "OFFLINE"}>'


# ==========================
# RATE LIMIT HELPER FUNCTIONS
# ==========================

def check_command_limit(user_id):
    today = datetime.utcnow().date()
    usage = CommandUsage.query.filter_by(user_id=user_id, command_date=today).first()
    if not usage:
        usage = CommandUsage(user_id=user_id, command_date=today, count=0)
        db.session.add(usage)
        db.session.commit()
    allowed = usage.count < 100
    remaining = 100 - usage.count if allowed else 0
    return allowed, usage.count, remaining

def increment_command_count(user_id):
    today = datetime.utcnow().date()
    usage = CommandUsage.query.filter_by(user_id=user_id, command_date=today).first()
    if not usage:
        usage = CommandUsage(user_id=user_id, command_date=today, count=0)
        db.session.add(usage)
    usage.count += 1
    db.session.commit()
    return usage.count

def check_login_limit(identifier, ip_address, max_attempts=10, window_hours=1):
    user = User.query.filter_by(email=identifier).first() or User.query.filter_by(username=identifier).first()
    
    if user and user.suspended_until and user.suspended_until > datetime.utcnow():
        remaining_seconds = (user.suspended_until - datetime.utcnow()).total_seconds()
        return False, int(remaining_seconds), user.suspended_until
    
    cutoff_time = datetime.utcnow() - timedelta(hours=window_hours)
    failed_attempts = LoginAttempt.query.filter(
        LoginAttempt.identifier == identifier,
        LoginAttempt.attempt_type == 'login',
        LoginAttempt.success == False,
        LoginAttempt.attempt_time >= cutoff_time
    ).count()
    
    if failed_attempts >= max_attempts and user:
        suspended_until = datetime.utcnow() + timedelta(hours=window_hours)
        user.suspended_until = suspended_until
        user.failed_login_count = failed_attempts
        db.session.commit()
        remaining_seconds = (suspended_until - datetime.utcnow()).total_seconds()
        return False, int(remaining_seconds), suspended_until
    
    return True, 0, None

def log_login_attempt(identifier, success, ip_address, user_agent=None, user_id=None, attempt_type='login'):
    attempt = LoginAttempt(
        identifier=identifier[:255],
        attempt_type=attempt_type,
        success=success,
        ip_address=ip_address[:50] if ip_address else None,
        user_agent=user_agent[:500] if user_agent else None,
        user_id=user_id
    )
    db.session.add(attempt)
    
    if success and user_id:
        user = User.query.get(user_id)
        if user and user.suspended_until:
            user.suspended_until = None
            user.failed_login_count = 0
    
    db.session.commit()

def cleanup_old_login_attempts(hours=24):
    cutoff_time = datetime.utcnow() - timedelta(hours=hours)
    deleted = LoginAttempt.query.filter(LoginAttempt.attempt_time < cutoff_time).delete()
    db.session.commit()
    return deleted

def get_user_command_stats(user_id, days=7):
    start_date = datetime.utcnow().date() - timedelta(days=days)
    usage_records = CommandUsage.query.filter(
        CommandUsage.user_id == user_id,
        CommandUsage.command_date >= start_date
    ).order_by(CommandUsage.command_date.desc()).all()
    
    daily_usage = {record.command_date.isoformat(): record.count for record in usage_records}
    total_commands = sum(record.count for record in usage_records)
    today = datetime.utcnow().date()
    today_usage = next((r.count for r in usage_records if r.command_date == today), 0)
    
    return {
        'daily_usage': daily_usage,
        'total_commands_last_7_days': total_commands,
        'commands_today': today_usage,
        'daily_limit': 100,
        'remaining_today': max(0, 100 - today_usage)
    }
# ==========================
# DATABASE MIGRATION HELPER
# ==========================

def run_migrations():
    try:
        from sqlalchemy import text
        print("\n🔄 Running database migrations...")
        
        # ========== SECURITY COLUMNS FOR USERS TABLE ==========
        security_columns_to_add = [
            ('ban_reason', "ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_reason VARCHAR(500)"),
            ('tamper_attempt_count', "ALTER TABLE users ADD COLUMN IF NOT EXISTS tamper_attempt_count INTEGER DEFAULT 0"),
            ('last_tamper_at', "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_tamper_at TIMESTAMP"),
            ('ban_type', "ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_type VARCHAR(50) DEFAULT 'manual'")
        ]
        
        for col_name, alter_statement in security_columns_to_add:
            try:
                db.session.execute(text(alter_statement))
                db.session.commit()
                print(f"✅ Added security column: {col_name}")
            except Exception as e:
                if "duplicate column" not in str(e).lower() and "already exists" not in str(e).lower():
                    print(f"⚠️ Could not add {col_name}: {e}")
                db.session.rollback()
        
        # ========== SECURITY TABLES (POSTGRESQL SYNTAX) ==========
        
        # Security Challenges Table
        try:
            db.session.execute(text("""
                CREATE TABLE IF NOT EXISTS security_challenges (
                    id SERIAL PRIMARY KEY,
                    challenge_id TEXT UNIQUE NOT NULL,
                    challenge TEXT NOT NULL,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    used BOOLEAN DEFAULT FALSE
                )
            """))
            db.session.commit()
            print("✅ Created security_challenges table")
        except Exception as e:
            print(f"⚠️ security_challenges table: {e}")
            db.session.rollback()
        
        # Challenge Logs Table
        try:
            db.session.execute(text("""
                CREATE TABLE IF NOT EXISTS challenge_logs (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    challenge_id TEXT NOT NULL,
                    success BOOLEAN DEFAULT FALSE,
                    device_fingerprint TEXT,
                    ip_address TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            db.session.commit()
            print("✅ Created challenge_logs table")
        except Exception as e:
            print(f"⚠️ challenge_logs table: {e}")
            db.session.rollback()
        
        # Tamper Reports Table
        try:
            db.session.execute(text("""
                CREATE TABLE IF NOT EXISTS tamper_reports (
                    id SERIAL PRIMARY KEY,
                    email TEXT NOT NULL,
                    device_fingerprint TEXT NOT NULL,
                    tamper_flags TEXT NOT NULL,
                    ip_address TEXT,
                    username TEXT,
                    hostname TEXT,
                    reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            db.session.commit()
            print("✅ Created tamper_reports table")
        except Exception as e:
            print(f"⚠️ tamper_reports table: {e}")
            db.session.rollback()
        
        # Tamper Counters Table
        try:
            db.session.execute(text("""
                CREATE TABLE IF NOT EXISTS tamper_counters (
                    email TEXT PRIMARY KEY,
                    tamper_count INTEGER DEFAULT 0,
                    last_tamper_at TIMESTAMP,
                    banned_at TIMESTAMP,
                    ban_reason TEXT
                )
            """))
            db.session.commit()
            print("✅ Created tamper_counters table")
        except Exception as e:
            print(f"⚠️ tamper_counters table: {e}")
            db.session.rollback()
        
        # ========== NEW DEVICE BINDING COLUMNS FOR USERS TABLE ==========
        binding_columns_to_add = [
            ('bound_hwid_hash', "ALTER TABLE users ADD COLUMN IF NOT EXISTS bound_hwid_hash VARCHAR(256)"),
            ('bound_pc_manufacturer', "ALTER TABLE users ADD COLUMN IF NOT EXISTS bound_pc_manufacturer VARCHAR(200)"),
            ('bound_windows_version', "ALTER TABLE users ADD COLUMN IF NOT EXISTS bound_windows_version VARCHAR(100)"),
            ('bound_hardware_fingerprint', "ALTER TABLE users ADD COLUMN IF NOT EXISTS bound_hardware_fingerprint VARCHAR(256)"),
            ('bound_system_info', "ALTER TABLE users ADD COLUMN IF NOT EXISTS bound_system_info TEXT"),
            ('bound_ip_address', "ALTER TABLE users ADD COLUMN IF NOT EXISTS bound_ip_address VARCHAR(50)"),
            ('bound_at', "ALTER TABLE users ADD COLUMN IF NOT EXISTS bound_at TIMESTAMP"),
            ('last_verified_at', "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMP"),
            ('verification_failures', "ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_failures INTEGER DEFAULT 0"),
            ('is_verified_device', "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified_device BOOLEAN DEFAULT FALSE"),
        ]
        
        for col_name, alter_statement in binding_columns_to_add:
            try:
                db.session.execute(text(alter_statement))
                db.session.commit()
                print(f"✅ Added column: {col_name}")
            except Exception as e:
                if "duplicate column" not in str(e).lower() and "already exists" not in str(e).lower():
                    print(f"⚠️ Could not add {col_name}: {e}")
                db.session.rollback()
        
        # New columns for devices table
        device_columns_to_add = [
            ('pc_manufacturer', "ALTER TABLE devices ADD COLUMN IF NOT EXISTS pc_manufacturer VARCHAR(200)"),
            ('windows_version', "ALTER TABLE devices ADD COLUMN IF NOT EXISTS windows_version VARCHAR(100)"),
            ('hardware_fingerprint', "ALTER TABLE devices ADD COLUMN IF NOT EXISTS hardware_fingerprint VARCHAR(256)"),
        ]
        
        for col_name, alter_statement in device_columns_to_add:
            try:
                db.session.execute(text(alter_statement))
                db.session.commit()
                print(f"✅ Added column to devices: {col_name}")
            except Exception as e:
                if "duplicate column" not in str(e).lower() and "already exists" not in str(e).lower():
                    print(f"⚠️ Could not add {col_name} to devices: {e}")
                db.session.rollback()
        
        # New columns for user_sessions table
        session_columns_to_add = [
            ('session_hwid_hash', "ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS session_hwid_hash VARCHAR(256)"),
            ('session_hardware_fingerprint', "ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS session_hardware_fingerprint VARCHAR(256)"),
            ('session_pc_manufacturer', "ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS session_pc_manufacturer VARCHAR(200)"),
            ('session_windows_version', "ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS session_windows_version VARCHAR(100)"),
        ]
        
        for col_name, alter_statement in session_columns_to_add:
            try:
                db.session.execute(text(alter_statement))
                db.session.commit()
                print(f"✅ Added column to user_sessions: {col_name}")
            except Exception as e:
                if "duplicate column" not in str(e).lower() and "already exists" not in str(e).lower():
                    print(f"⚠️ Could not add {col_name} to user_sessions: {e}")
                db.session.rollback()
        
        # Create indexes for new columns
        indexes_to_create = [
            'CREATE INDEX IF NOT EXISTS idx_users_bound_hwid ON users(bound_hwid_hash) WHERE bound_hwid_hash IS NOT NULL;',
            'CREATE INDEX IF NOT EXISTS idx_users_bound_fingerprint ON users(bound_hardware_fingerprint) WHERE bound_hardware_fingerprint IS NOT NULL;',
            'CREATE INDEX IF NOT EXISTS idx_users_verified_device ON users(is_verified_device) WHERE is_verified_device = true;',
            'CREATE INDEX IF NOT EXISTS idx_devices_hardware_fingerprint ON devices(hardware_fingerprint);',
            'CREATE INDEX IF NOT EXISTS idx_sessions_hwid ON user_sessions(session_hwid_hash);',
            'CREATE INDEX IF NOT EXISTS idx_tamper_reports_email ON tamper_reports(email);',
            'CREATE INDEX IF NOT EXISTS idx_tamper_reports_reported_at ON tamper_reports(reported_at);',
            'CREATE INDEX IF NOT EXISTS idx_challenge_logs_user_id ON challenge_logs(user_id);',
            'CREATE INDEX IF NOT EXISTS idx_challenge_logs_created_at ON challenge_logs(created_at);',
            'CREATE INDEX IF NOT EXISTS idx_security_challenges_user_id ON security_challenges(user_id);',
            'CREATE INDEX IF NOT EXISTS idx_security_challenges_expires_at ON security_challenges(expires_at);',
        ]
        
        for index_statement in indexes_to_create:
            try:
                db.session.execute(text(index_statement))
                db.session.commit()
                print(f"✅ Created index")
            except Exception as e:
                print(f"⚠️ Could not create index: {e}")
                db.session.rollback()
        
        # Update device_history action constraint
        try:
            db.session.execute(text("ALTER TABLE device_history DROP CONSTRAINT IF EXISTS check_device_action"))
            db.session.commit()
            db.session.execute(text("""
                ALTER TABLE device_history ADD CONSTRAINT check_device_action 
                CHECK (action IN (
                    'register','unregister','reset','change_pc','login','logout',
                    'admin_deleted','reactivate','session_created','session_expired',
                    'admin_reset_all','admin_reset_single','admin_toggle_trust',
                    'reset_all','reset_single','device_bound','device_mismatch'
                ))
            """))
            db.session.commit()
            print("✅ Updated device_history action constraint")
        except Exception as e:
            print(f"⚠️ device_history constraint: {e}")
            db.session.rollback()
        
        # Update credit_transactions constraint to include reseller_gift
        try:
            db.session.execute(text("ALTER TABLE credit_transactions DROP CONSTRAINT IF EXISTS check_transaction_type"))
            db.session.commit()
            db.session.execute(text("""
                ALTER TABLE credit_transactions ADD CONSTRAINT check_transaction_type 
                CHECK (transaction_type IN (
                    'admin_add','admin_deduct','purchase','usage','refund','commission',
                    'device_reset','pc_change','device_registration','credit_used','hwid_reset',
                    'otp_purchase','samsung_frp_order','reseller_gift'
                ))
            """))
            db.session.commit()
            print("✅ Updated transaction_type constraint with reseller_gift")
        except Exception as e:
            print(f"⚠️ transaction_type constraint: {e}")
            db.session.rollback()
        
        print("✅ Database migrations completed successfully")
    except Exception as e:
        print(f"❌ Database migration error: {e}")
        print("⚠️ Continuing despite migration error...")


# ==========================
# POSTGRESQL OPTIMIZATION FUNCTIONS
# ==========================

def create_postgres_indexes():
    indexes = [
        'CREATE INDEX IF NOT EXISTS idx_users_license_status ON users(license_status);',
        'CREATE INDEX IF NOT EXISTS idx_users_license_type ON users(license_type);',
        'CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);',
        'CREATE INDEX IF NOT EXISTS idx_users_reset_token ON users(reset_token) WHERE reset_token IS NOT NULL;',
        'CREATE INDEX IF NOT EXISTS idx_users_is_reseller ON users(is_reseller) WHERE is_reseller = true;',
        'CREATE INDEX IF NOT EXISTS idx_credit_transactions_user ON credit_transactions(user_id, created_at);',
        'CREATE INDEX IF NOT EXISTS idx_credit_transactions_type ON credit_transactions(transaction_type);',
        'CREATE INDEX IF NOT EXISTS idx_users_bound_hwid ON users(bound_hwid_hash) WHERE bound_hwid_hash IS NOT NULL;',
        'CREATE INDEX IF NOT EXISTS idx_users_bound_fingerprint ON users(bound_hardware_fingerprint) WHERE bound_hardware_fingerprint IS NOT NULL;',
        'CREATE INDEX IF NOT EXISTS idx_devices_hardware_fingerprint ON devices(hardware_fingerprint);',
        # Security table indexes for PostgreSQL
        'CREATE INDEX IF NOT EXISTS idx_tamper_reports_email ON tamper_reports(email);',
        'CREATE INDEX IF NOT EXISTS idx_tamper_reports_reported_at ON tamper_reports(reported_at);',
        'CREATE INDEX IF NOT EXISTS idx_challenge_logs_user_id ON challenge_logs(user_id);',
        'CREATE INDEX IF NOT EXISTS idx_challenge_logs_created_at ON challenge_logs(created_at);',
        'CREATE INDEX IF NOT EXISTS idx_security_challenges_user_id ON security_challenges(user_id);',
        'CREATE INDEX IF NOT EXISTS idx_security_challenges_expires_at ON security_challenges(expires_at);',
    ]
    return indexes
