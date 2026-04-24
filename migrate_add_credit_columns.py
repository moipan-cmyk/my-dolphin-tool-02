#!/usr/bin/env python
"""
Migration script to add missing credit columns to the users table.
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
            columns_to_add = [
                ('credits', "ALTER TABLE users ADD COLUMN credits INTEGER DEFAULT 0"),
                ('commission_rate', "ALTER TABLE users ADD COLUMN commission_rate INTEGER DEFAULT 15"),
                ('total_sales', "ALTER TABLE users ADD COLUMN total_sales INTEGER DEFAULT 0"),
                ('total_commission', "ALTER TABLE users ADD COLUMN total_commission INTEGER DEFAULT 0"),
                ('activated_by', "ALTER TABLE users ADD COLUMN activated_by INTEGER REFERENCES users(id) ON DELETE SET NULL"),
                ('last_login', "ALTER TABLE users ADD COLUMN last_login TIMESTAMP"),
            ]
            
            for col_name, alter_statement in columns_to_add:
                try:
                    # Check if column exists
                    result = connection.execute(text(f"""
                        SELECT column_name FROM information_schema.columns 
                        WHERE table_name='users' AND column_name='{col_name}'
                    """))
                    has_column = result.fetchone() is not None
                    
                    if not has_column:
                        print(f"Adding {col_name} column...")
                        try:
                            connection.execute(text(alter_statement))
                            connection.commit()
                            print(f"✅ {col_name} column added successfully")
                        except Exception as e:
                            print(f"❌ Error adding {col_name}: {e}")
                            connection.rollback()
                    else:
                        print(f"✅ {col_name} column already exists")
                except Exception as e:
                    print(f"Error checking {col_name}: {e}")

if __name__ == '__main__':
    print("Starting credit columns migration...")
    check_and_add_columns()
    print("Migration complete!")