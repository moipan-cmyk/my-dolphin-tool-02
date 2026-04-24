# routes/__init__.py
"""Routes package initialization"""

import os
import sys

print("\n🔄 Initializing routes package...")
print(f"📂 Routes __init__.py location: {__file__}")
print(f"📂 Routes directory contents: {os.listdir(os.path.dirname(__file__))}")

# Import blueprints from your actual files (with _routes suffix)
try:
    from .main_routes import main_bp
    from .auth_routes import auth_bp
    from .admin_routes import admin_bp
    from .reseller_routes import reseller_bp
    from .license_routes import license_bp

    __all__ = ['main_bp', 'auth_bp', 'admin_bp', 'reseller_bp', 'license_bp']
    print(f"✅ Routes package initialized successfully")
    print(f"   Available blueprints: {__all__}")
except ImportError as e:
    print(f"❌ Error initializing routes package: {e}")
    print("\n💡 Troubleshooting tips:")
    print("   1. Check that all files exist in the routes directory:")
    print("      - main_routes.py")
    print("      - auth_routes.py") 
    print("      - admin_routes.py")
    print("      - reseller_routes.py")
    print("      - license_routes.py")
    print("   2. Verify each file exports the correct blueprint variable")
    print("   3. Check for syntax errors in the route files")
    raise