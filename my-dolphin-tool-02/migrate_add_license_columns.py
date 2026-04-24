#!/usr/bin/env python
"""
Migration script to add missing license columns to the users table.
Run this once to update the Render database schema.
"""

import os
from flask import Flask
from database import db, User
from config import Config
from sqlalchemy import text

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

def check_and_add_columns():
    """Check if columns exist and add them if needed"""
    with app.app_context():
        with db.engine.connect() as connection:
            # Check for license_type column
            try:
                result = connection.execute(text("""
                    SELECT column_name FROM information_schema.columns 
                    WHERE table_name='users' AND column_name='license_type'
                """))
                has_license_type = result.fetchone() is not None
            except Exception as e:
                print(f"Error checking license_type column: {e}")
                has_license_type = False
            
            # Check for license_status column
            try:
                result = connection.execute(text("""
                    SELECT column_name FROM information_schema.columns 
                    WHERE table_name='users' AND column_name='license_status'
                """))
                has_license_status = result.fetchone() is not None
            except Exception as e:
                print(f"Error checking license_status column: {e}")
                has_license_status = False
            
            # Add missing columns
            if not has_license_type:
                print("Adding license_type column...")
                try:
                    connection.execute(text("""
                        ALTER TABLE users ADD COLUMN license_type VARCHAR(20) DEFAULT 'None' NOT NULL
                    """))
                    connection.commit()
                    print("✅ license_type column added successfully")
                except Exception as e:
                    print(f"❌ Error adding license_type: {e}")
                    connection.rollback()
            else:
                print("✅ license_type column already exists")
            
            if not has_license_status:
                print("Adding license_status column...")
                try:
                    connection.execute(text("""
                        ALTER TABLE users ADD COLUMN license_status VARCHAR(20) DEFAULT 'inactive'
                    """))
                    connection.commit()
                    print("✅ license_status column added successfully")
                except Exception as e:
                    print(f"❌ Error adding license_status: {e}")
                    connection.rollback()
            else:
                print("✅ license_status column already exists")

if __name__ == '__main__':
    print("Starting migration...")
    check_and_add_columns()
    print("Migration complete!")
