import streamlit as st
import sqlite3
from pathlib import Path
import hashlib

def create_connection():
    db_path = Path(__file__).parent.parent / "database" / "fyp.db"
    return sqlite3.connect(str(db_path))

def init_admin():
    conn = create_connection()
    cursor = conn.cursor()
    
    # Check if admin user exists
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if cursor.fetchone() is None:
        # Create admin user with password 'admin'
        hashed_password = hashlib.sha256('admin'.encode()).hexdigest()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                      ('admin', hashed_password))
        conn.commit()
    conn.close()

def verify_credentials(username, password):
    conn = create_connection()
    cursor = conn.cursor()
    
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", 
                  (username, hashed_password))
    user = cursor.fetchone()
    conn.close()
    
    return user is not None

def login_page():
    st.title("Login")
    
    # Initialize admin user if not exists
    init_admin()
    
    # Create login form
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
        
        if submit:
            if verify_credentials(username, password):
                st.session_state['authenticated'] = True
                st.session_state['username'] = username
                st.success("Login successful!")
                st.rerun()
            else:
                st.error("Invalid username or password")

if __name__ == "__main__":
    if 'authenticated' not in st.session_state:
        st.session_state['authenticated'] = False
        
    if not st.session_state['authenticated']:
        login_page()
    else:
        st.success(f"Welcome {st.session_state['username']}!")
        if st.button("Logout"):
            st.session_state['authenticated'] = False
            st.rerun()