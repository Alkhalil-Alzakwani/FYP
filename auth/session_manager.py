"""
auth/session_manager.py

Handles:

    Session creation and expiration

    Storing minimal data in Streamlit’s st.session_state

    Optional JWT token usage for stateless design

Key variables:

    SESSION_TIMEOUT_MINUTES = 30

    SECRET_KEY stored in config/security.yaml
"""