"""
Database Initialization Script for PostgreSQL
Run this once to set up the PostgreSQL database and tables
"""

import os
import sys
from dotenv import load_dotenv
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

load_dotenv()

def check_postgres_connection():
    """Check if PostgreSQL is running and accessible"""
    try:
        # Try to connect using SQLAlchemy URI from config
        from config import Config
        
        # Parse connection string for testing
        if Config.DATABASE_URL:
            # For Render or DATABASE_URL
            conn = psycopg2.connect(Config.DATABASE_URL)
        else:
            # For local connection
            conn = psycopg2.connect(
                host=Config.PG_HOST,
                user=Config.PG_USER,
                password=Config.PG_PASSWORD,
                database=Config.PG_DB,
                port=Config.PG_PORT
            )
        conn.close()
        return True, "Connected successfully"
    except psycopg2.OperationalError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)

def create_database_if_not_exists():
    """Create the database if it doesn't exist (local PostgreSQL only)"""
    try:
        from config import Config
        
        # Skip for Render (database is created automatically)
        if Config.DATABASE_URL:
            return True, "Using Render PostgreSQL"
        
        # Connect to default postgres database to create new database
        conn = psycopg2.connect(
            host=Config.PG_HOST,
            user=Config.PG_USER,
            password=Config.PG_PASSWORD,
            database='postgres',  # Connect to default database
            port=Config.PG_PORT
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        # Check if database exists
        cursor.execute(f"SELECT 1 FROM pg_database WHERE datname = '{Config.PG_DB}'")
        exists = cursor.fetchone()
        
        if not exists:
            print(f"   📁 Creating database: {Config.PG_DB}")
            cursor.execute(f"CREATE DATABASE {Config.PG_DB}")
            print(f"   ✓ Database created successfully")
        else:
            print(f"   ✓ Database already exists")
        
        cursor.close()
        conn.close()
        return True, "Database ready"
        
    except Exception as e:
        return False, str(e)

def setup_database():
    """Initialize the database"""
    try:
        from app import app, db
        from database import User, SystemLog, PatchRequest, Device, LicenseTransaction
        
        print("="*70)
        print("🐬 DOLPHIN BYPASS TOOL - PostgreSQL Database Setup")
        print("="*70)
        
        # Step 1: Check PostgreSQL connection
        print("\n1. Checking PostgreSQL connection...")
        connected, message = check_postgres_connection()
        if connected:
            print(f"   ✓ PostgreSQL is running: {message}")
        else:
            print(f"   ✗ Connection failed: {message}")
            print("\nTroubleshooting:")
            print("   • Make sure PostgreSQL is installed and running")
            print("   • Check credentials in .env file")
            print("   • For Windows: run 'pg_ctl start' or start PostgreSQL service")
            print("   • For Render: DATABASE_URL is automatically provided")
            sys.exit(1)
        
        # Step 2: Create database if needed (local only)
        print("\n2. Checking/Creating database...")
        created, message = create_database_if_not_exists()
        if created:
            print(f"   ✓ {message}")
        else:
            print(f"   ✗ {message}")
            sys.exit(1)
        
        # Step 3: Create tables
        print("\n3. Creating database tables...")
        with app.app_context():
            # Create all tables
            db.create_all()
            print("   ✓ All tables created successfully")
            
            # Create PostgreSQL-specific indexes
            try:
                from database import create_postgres_indexes
                print("\n4. Creating indexes...")
                for i, index_sql in enumerate(create_postgres_indexes(), 1):
                    try:
                        db.session.execute(index_sql)
                        db.session.commit()
                        print(f"   ✓ Index {i} created")
                    except Exception as e:
                        db.session.rollback()
                        print(f"   ⚠ Index {i} skipped (may already exist): {e}")
            except ImportError:
                print("   ⚠ No index creation function found")
            
            # Step 5: Verify tables
            print("\n5. Verifying tables...")
            try:
                # Get list of tables
                result = db.session.execute("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_schema = 'public'
                    ORDER BY table_name;
                """).fetchall()
                
                tables = [row[0] for row in result]
                print(f"   ✓ Tables in database: {', '.join(tables)}")
                
                # Check user count
                user_count = User.query.count()
                print(f"   ✓ Current users in database: {user_count}")
                
                # Check if admin user exists
                admin_exists = User.query.filter_by(is_admin=True).first() is not None
                if admin_exists:
                    print(f"   ✓ Admin user exists")
                else:
                    print(f"   ⚠ No admin user found. Run 'flask create-admin' to create one.")
                
            except Exception as e:
                print(f"   ⚠ Could not verify tables: {e}")
        
        print("\n" + "="*70)
        print("✅ DATABASE SETUP COMPLETE!")
        print("="*70)
        print("\n📋 NEXT STEPS:")
        print("   1. Create a .env file (if not already done):")
        print("      cp .env.example .env")
        print("")
        print("   2. Update PostgreSQL credentials in .env:")
        print("      • For local PostgreSQL:")
        print("        PG_HOST=localhost")
        print("        PG_USER=postgres")
        print("        PG_PASSWORD=your_password")
        print("        PG_DB=dolphin_bypass_db")
        print("      • For Render (automatic):")
        print("        DATABASE_URL=postgresql://...")
        print("")
        print("   3. Update email credentials in .env (for sending emails):")
        print("      SENDER_EMAIL=your-email@gmail.com")
        print("      SENDER_PASSWORD=your-app-password")
        print("")
        print("   4. Create an admin user:")
        print("      flask create-admin")
        print("")
        print("   5. Start the Flask server:")
        print("      python app.py")
        print("      # or for production:")
        print("      gunicorn app:app")
        print("")
        print("   6. Access the web interface:")
        print("      http://localhost:5000")
        print("")
        print("   7. Run the desktop GUI:")
        print("      python your_main_gui.py")
        print("")
        print("="*70)
        
    except ImportError as e:
        print(f"\n✗ Import Error:")
        print(f"   {str(e)}")
        print("\nMake sure all dependencies are installed:")
        print("   pip install -r requirements.txt")
        sys.exit(1)
        
    except Exception as e:
        print(f"\n✗ Error setting up database:")
        print(f"   {str(e)}")
        print("\nTroubleshooting:")
        print("   1. Make sure PostgreSQL is running:")
        print("      • Windows: Check Services (postgresql-x64)")
        print("      • Linux: sudo systemctl status postgresql")
        print("      • Mac: brew services list | grep postgres")
        print("   2. Check .env file for correct credentials")
        print("   3. Make sure the database user has CREATE DATABASE privileges")
        print("   4. For Render: DATABASE_URL should be set automatically")
        sys.exit(1)

def quick_check():
    """Quick check of database status"""
    try:
        from app import app, db
        from database import User
        
        with app.app_context():
            user_count = User.query.count()
            admin_count = User.query.filter_by(is_admin=True).count()
            
            print("\n" + "="*40)
            print("📊 DATABASE STATUS")
            print("="*40)
            print(f"Total users: {user_count}")
            print(f"Admin users: {admin_count}")
            
            # License stats
            fair_users = User.query.filter_by(license_type='Fair').count()
            good_users = User.query.filter_by(license_type='Good').count()
            excellent_users = User.query.filter_by(license_type='Excellent').count()
            no_license = User.query.filter_by(license_type='None').count()
            
            print("\n📋 LICENSE DISTRIBUTION:")
            print(f"   Fair (3 months): {fair_users}")
            print(f"   Good (6 months): {good_users}")
            print(f"   Excellent (12 months): {excellent_users}")
            print(f"   No License: {no_license}")
            
            # Expiring soon
            from datetime import datetime, timedelta
            expiring_soon = User.query.filter(
                User.license_expiry_date <= datetime.utcnow() + timedelta(days=7),
                User.license_expiry_date > datetime.utcnow(),
                User.license_type != 'None'
            ).count()
            
            print(f"\n⚠️ Licenses expiring in 7 days: {expiring_soon}")
            
            print("\n✅ Database is healthy!")
            print("="*40)
            
    except Exception as e:
        print(f"\n✗ Error checking database: {e}")

if __name__ == "__main__":
    # Check for quick check flag
    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        quick_check()
    else:
        setup_database()