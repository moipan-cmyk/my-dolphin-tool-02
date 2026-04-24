import os
from dotenv import load_dotenv
from urllib.parse import quote_plus

load_dotenv()


class Config:
    # ------------------------------
    # FLASK SECURITY
    # ------------------------------
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Session configuration for web interface
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 86400  # 24 hours in seconds

    # ------------------------------
    # POSTGRESQL CONFIG
    # ------------------------------
    # Support both Render's DATABASE_URL and manual config
    DATABASE_URL = os.getenv('DATABASE_URL')
    
    # Also check for individual components (Render sometimes provides these separately)
    DB_HOST = os.getenv('DB_HOST')
    DB_PORT = os.getenv('DB_PORT', '5432')
    DB_USER = os.getenv('DB_USER')
    DB_PASSWORD = os.getenv('DB_PASSWORD')
    DB_NAME = os.getenv('DB_NAME')

    # Fix incomplete hostname if needed
    if DB_HOST and not DB_HOST.endswith('.com') and not DB_HOST.endswith('.net'):
        # Add the Render domain if missing
        if 'oregon-postgres.render.com' not in DB_HOST:
            DB_HOST = f"{DB_HOST}.oregon-postgres.render.com"
            print(f"✅ Fixed DB_HOST to: {DB_HOST}")

    # Construct DATABASE_URL from individual components if needed
    if not DATABASE_URL and DB_USER and DB_PASSWORD and DB_HOST and DB_NAME:
        encoded_password = quote_plus(DB_PASSWORD)
        DATABASE_URL = f"postgresql://{DB_USER}:{encoded_password}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
        print(f"✅ Constructed DATABASE_URL from components")

    if DATABASE_URL:
        # Use Render's DATABASE_URL directly
        SQLALCHEMY_DATABASE_URI = DATABASE_URL
        # Fix for postgres:// vs postgresql://
        if SQLALCHEMY_DATABASE_URI and SQLALCHEMY_DATABASE_URI.startswith('postgres://'):
            SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace('postgres://', 'postgresql://', 1)
        
        # Fix incomplete hostname in DATABASE_URL
        if 'dpg-' in SQLALCHEMY_DATABASE_URI and '.com' not in SQLALCHEMY_DATABASE_URI:
            # Replace the incomplete hostname with full hostname
            import re
            match = re.search(r'dpg-[a-zA-Z0-9]+', SQLALCHEMY_DATABASE_URI)
            if match:
                old_host = match.group()
                new_host = f"{old_host}.oregon-postgres.render.com"
                SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace(old_host, new_host)
                print(f"✅ Fixed DATABASE_URL hostname: {old_host} -> {new_host}")
        
        print(f"✅ Database URI configured (host: {SQLALCHEMY_DATABASE_URI.split('@')[1].split('/')[0] if '@' in SQLALCHEMY_DATABASE_URI else 'unknown'})")
    else:
        # Fallback to SQLite for local development
        SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///local.db')
        print(f"⚠️ Using SQLite database: {SQLALCHEMY_DATABASE_URI}")

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Connection pool settings for production
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': int(os.getenv('DB_POOL_SIZE', 10)),
        'pool_recycle': int(os.getenv('DB_POOL_RECYCLE', 300)),
        'pool_pre_ping': True,  # Verifies connections before using
    }

    # ------------------------------
    # FILE UPLOAD (if used in future)
    # ------------------------------
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'static/uploads')
    MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_LENGTH', 500 * 1024 * 1024))  # 500MB
    ALLOWED_EXTENSIONS = {'img', 'bin'}

    # ------------------------------
    # EMAIL SMTP CONFIGURATION
    # ------------------------------
    # SMTP Server Settings
    SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
    SMTP_USER = os.getenv('SMTP_USER', os.getenv('SENDER_EMAIL'))
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', os.getenv('SENDER_PASSWORD'))
    FROM_EMAIL = os.getenv('FROM_EMAIL', SMTP_USER)
    
    # Email Settings (compatibility with both old and new variable names)
    MAIL_SERVER = SMTP_SERVER
    MAIL_PORT = SMTP_PORT
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USERNAME = SMTP_USER
    MAIL_PASSWORD = SMTP_PASSWORD
    MAIL_DEFAULT_SENDER = FROM_EMAIL
    
    # Application Settings for Email Links
    APP_NAME = os.getenv('APP_NAME', 'Dolphin Bypass Tool')
    APP_URL = os.getenv('APP_URL', 'https://my-mdm-tool.onrender.com')  # Fixed URL
    BASE_URL = APP_URL  # Alias for compatibility
    
    # For local development, you can override APP_URL
    if os.getenv('FLASK_ENV') == 'development':
        APP_URL = os.getenv('DEV_APP_URL', 'http://localhost:5000')
        BASE_URL = APP_URL

    # ------------------------------
    # LICENSE SETTINGS
    # ------------------------------
    # License durations in days
    LICENSE_DURATION_FAIR = int(os.getenv('LICENSE_DURATION_FAIR', 90))        # 3 months
    LICENSE_DURATION_GOOD = int(os.getenv('LICENSE_DURATION_GOOD', 180))       # 6 months
    LICENSE_DURATION_EXCELLENT = int(os.getenv('LICENSE_DURATION_EXCELLENT', 365))  # 12 months
    
    # Device limits per license type
    DEVICE_LIMIT_FAIR = int(os.getenv('DEVICE_LIMIT_FAIR', 10))
    DEVICE_LIMIT_GOOD = int(os.getenv('DEVICE_LIMIT_GOOD', 25))
    DEVICE_LIMIT_EXCELLENT = int(os.getenv('DEVICE_LIMIT_EXCELLENT', 55))
    
    # License prices (for future payment integration)
    LICENSE_PRICE_FAIR = float(os.getenv('LICENSE_PRICE_FAIR', 29.99))
    LICENSE_PRICE_GOOD = float(os.getenv('LICENSE_PRICE_GOOD', 49.99))
    LICENSE_PRICE_EXCELLENT = float(os.getenv('LICENSE_PRICE_EXCELLENT', 89.99))

    # ------------------------------
    # CORE MODULES CONFIGURATION
    # ------------------------------
    # Directory where core modules are stored for serving to clients
    CORE_MODULES_DIR = os.getenv('CORE_MODULES_DIR', os.path.join(os.path.dirname(__file__), 'core_modules'))
    
    # Module encryption key for client-server communication
    MODULE_ENCRYPTION_KEY = os.getenv('MODULE_ENCRYPTION_KEY', 'my-secret-key-change-this-in-production')
    
    # List of available modules (for validation)
    AVAILABLE_MODULES = ['adb', 'fastboot', 'mdm', 'mtp', 'unisoc', 'meta', 'bootrom', 'hxd', 'xiaomi']
    
    # Module version tracking (for cache invalidation)
    MODULE_VERSIONS = {
        'adb': '1.0.0',
        'fastboot': '1.0.0',
        'mdm': '1.0.0',
        'mtp': '1.0.0',
        'unisoc': '1.0.0',
        'xiaomi': '1.0.0',
        'meta': '1.0.0',
        'bootrom': '1.0.0',
        'hxd': '1.0.0',
    }

    # ------------------------------
    # PASSWORD RESET SETTINGS
    # ------------------------------
    RESET_TOKEN_EXPIRY_HOURS = int(os.getenv('RESET_TOKEN_EXPIRY_HOURS', 1))
    SESSION_DURATION_HOURS = int(os.getenv('SESSION_DURATION_HOURS', 12))

    # ------------------------------
    # COUNTRY LIST (Optional)
    # ------------------------------
    # List of supported countries for registration
    SUPPORTED_COUNTRIES = [
        'Kenya', 'Uganda', 'Tanzania', 'Nigeria', 'South Africa', 
        'Ghana', 'Egypt', 'India', 'America', 'Morocco', 'Algeria', 'Ethiopia',
        'Other'
    ]

    # ------------------------------
    # DEVICE & RATE LIMITING
    # ------------------------------
    DEVICE_LIMIT = int(os.getenv('DEVICE_LIMIT', 2))
    
    # Rate limiting (if you implement it later)
    RATE_LIMIT_PER_HOUR = int(os.getenv('RATE_LIMIT_PER_HOUR', 10))

    # ------------------------------
    # HELPER METHODS
    # ------------------------------
    @classmethod
    def is_email_configured(cls):
        """Check if email is properly configured for sending"""
        return bool(cls.SMTP_USER and cls.SMTP_PASSWORD and 
                   cls.SMTP_USER != 'your-email@gmail.com' and 
                   cls.SMTP_PASSWORD != 'your-app-specific-password')

    @classmethod
    def get_email_config(cls):
        """Get email configuration as a dictionary"""
        return {
            'server': cls.SMTP_SERVER,
            'port': cls.SMTP_PORT,
            'user': cls.SMTP_USER,
            'password': cls.SMTP_PASSWORD,
            'from_email': cls.FROM_EMAIL,
            'app_name': cls.APP_NAME,
            'base_url': cls.BASE_URL,
            'configured': cls.is_email_configured()
        }
    
    @classmethod
    def get_module_version(cls, module_name):
        """Get the version of a specific module"""
        return cls.MODULE_VERSIONS.get(module_name, '1.0.0')
    
    @classmethod
    def is_module_available(cls, module_name):
        """Check if a module is available"""
        return module_name in cls.AVAILABLE_MODULES
    
    @classmethod
    def get_module_info(cls, module_name):
        """Get information about a module"""
        if not cls.is_module_available(module_name):
            return None
        return {
            'name': module_name,
            'version': cls.get_module_version(module_name),
            'available': True
        }

    def __repr__(self):
        return f'<Config (Environment: {os.getenv("FLASK_ENV", "production")})>'