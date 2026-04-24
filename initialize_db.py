#!/usr/bin/env python
"""
Initialize database schema - run this once on Render after updating the code.
Add these commands to your Render Deploy Hook or run manually:
  python initialize_db.py
"""

import os
import sys
from flask import Flask
from database import db, User, SystemLog, PatchRequest, Device
from config import Config
from sqlalchemy import text, inspect

def init_database():
    """Initialize database and ensure all columns exist"""
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    
    with app.app_context():
        print("🔍 Checking database schema...")
        
        # Create tables if they don't exist
        db.create_all()
        print("✅ Tables created/verified")
        
        # Check and add missing columns
        inspector = inspect(db.engine)
        users_columns = [col['name'] for col in inspector.get_columns('users')]
        
        required_columns = {
            'license_type': "VARCHAR(20) DEFAULT 'None' NOT NULL",
            'license_status': "VARCHAR(20) DEFAULT 'inactive'",
            'is_admin': "BOOLEAN DEFAULT false",
            'is_reseller': "BOOLEAN DEFAULT false",
            'reset_token': "VARCHAR(100)",
            'reset_token_expiry': "TIMESTAMP"
        }
        
        with db.engine.begin() as connection:
            for column_name, column_def in required_columns.items():
                if column_name not in users_columns:
                    try:
                        print(f"📝 Adding column: {column_name}")
                        connection.execute(text(f"ALTER TABLE users ADD COLUMN {column_name} {column_def}"))
                        print(f"✅ Column {column_name} added successfully")
                    except Exception as e:
                        if "already exists" in str(e):
                            print(f"✅ Column {column_name} already exists")
                        else:
                            print(f"⚠️  Warning adding {column_name}: {e}")
                else:
                    print(f"✅ Column {column_name} exists")
        
        print("\n✅ Database initialization complete!")
        return True

if __name__ == '__main__':
    try:
        init_database()
        print("\n🎉 Success! Your database is now ready.")
    except Exception as e:
        print(f"\n❌ Error during initialization: {e}")
        sys.exit(1)
