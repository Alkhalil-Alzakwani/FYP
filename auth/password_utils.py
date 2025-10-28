"""
auth/password_utils.py

Handles password security.

Functions:

    hash_password(plain_password) → returns bcrypt hash

    verify_password(plain_password, hash) → compares hashes securely

Library: bcrypt
"""

import bcrypt


def hash_password(plain_password):
    """
    Hash a plain text password using bcrypt
    
    Args:
        plain_password (str): The plain text password to hash
        
    Returns:
        str: The hashed password
    """
    # Convert password to bytes
    password_bytes = plain_password.encode('utf-8')
    
    # Generate salt and hash the password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    
    # Return as string
    return hashed.decode('utf-8')


def verify_password(plain_password, password_hash):
    """
    Verify a plain text password against a bcrypt hash
    
    Args:
        plain_password (str): The plain text password to verify
        password_hash (str): The hashed password to compare against
        
    Returns:
        bool: True if password matches, False otherwise
    """
    try:
        # Convert both to bytes
        password_bytes = plain_password.encode('utf-8')
        hash_bytes = password_hash.encode('utf-8')
        
        # Compare
        return bcrypt.checkpw(password_bytes, hash_bytes)
    except Exception as e:
        print(f"Error verifying password: {e}")
        return False