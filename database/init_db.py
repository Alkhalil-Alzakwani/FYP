"""
database/init_db.py

Initialize the database with schema and create default admin user
"""

import sqlite3
from pathlib import Path
import sys

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from auth.password_utils import hash_password


def init_database():
    """Initialize the database with schema and create admin user"""
    
    db_path = Path(__file__).parent / "cyber_defense.db"
    schema_path = Path(__file__).parent / "schema.sql"
    
    print(f"Initializing database at: {db_path}")
    
    # Create database connection
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    # Read and execute schema
    print("Creating database schema...")
    with open(schema_path, 'r') as f:
        schema = f.read()
        cursor.executescript(schema)
    
    # Check if admin user already exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    admin_exists = cursor.fetchone()[0] > 0
    
    if not admin_exists:
        print("Creating default admin user...")
        
        # Create admin user (username: admin, password: admin)
        admin_password_hash = hash_password('admin')
        
        cursor.execute(
            """INSERT INTO users (username, password_hash, role, email, created_at, active) 
               VALUES (?, ?, ?, ?, datetime('now'), ?)""",
            ('admin', admin_password_hash, 'admin', 'admin@cyberdefense.local', 1)
        )
        
        print("[SUCCESS] Admin user created successfully!")
        print("   Username: admin")
        print("   Password: admin")
        print("   [WARNING] Please change the default password after first login!")
    else:
        print("[INFO] Admin user already exists")
    
    # Commit and close
    conn.commit()
    conn.close()
    
    print("[SUCCESS] Database initialization completed successfully!")
    return True


if __name__ == "__main__":
    try:
        init_database()
    except Exception as e:
        print(f"[ERROR] Error initializing database: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)