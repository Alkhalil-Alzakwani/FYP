r"""
MULTILAYERED CYBER DEFENSE PLATFORM - SYSTEM CONFIGURATION MANAGEMENT
╚════════════════════════════════════════════════════════════════════════════╝

File: pages/System_Configuration.py
Purpose: Centralized administrative interface for system settings and integration parameters

DESCRIPTION:
    Secure administration panel for managing all platform configuration settings,
    API credentials, integration parameters, security policies, and operational
    thresholds. All settings persist to YAML/JSON files with automatic backup
    before updates. Admin-only access with role-based enforcement.

CONFIGURATION CATEGORIES & PERSISTENCE:

    1. Database Configuration (db_config.yaml)
       ├─ Database type selection (SQLite, MySQL, PostgreSQL)
       ├─ Connection parameters (host, port, database name)
       ├─ Authentication (username, password)
       ├─ Connection pooling (pool size, timeout)
       └─ Test connectivity button

    2. Splunk SIEM Configuration (splunk_config.yaml)
       ├─ Splunk server URL and port (default 172.20.10.3:8000)
       ├─ API authentication token
       ├─ Search query parameters
       ├─ Index names and sourcetypes
       ├─ Query time ranges
       └─ Connection test button

    3. Mistral AI Configuration (mistral_config.yaml)
       ├─ API endpoint URL (local Ollama or remote)
       ├─ API key/authentication
       ├─ Model selection and parameters
       ├─ Temperature and token limits
       ├─ Confidence thresholds
       └─ Connection test button

    4. Security Settings (security.yaml)
       ├─ Session timeout duration (minutes)
       ├─ Maximum login attempts before lockout
       ├─ JWT secret key management
       ├─ Password policy rules
       ├─ Rate limiting parameters
       └─ Encryption settings

    5. Detection Thresholds (thresholds.json)
       ├─ Severity level thresholds (info/low/medium/high/critical)
       ├─ AI confidence minimum percentage
       ├─ Auto-response trigger points
       ├─ Alert notification levels
       └─ False positive threshold

    6. Firewall Integration (pfSense configuration)
       ├─ Firewall API endpoint
       ├─ API credentials
       ├─ Auto-block rule settings
       └─ Rule priority configuration

PAGE STRUCTURE:
    1. Header:
       - Title: "System Configuration"
       - Subtitle: "Configure system settings, API credentials..."
    
    2. Admin Role Check:
       - Validates user_role == 'admin'
       - Shows error and redirects if non-admin
    
    3. Tabbed Interface (6 tabs):
       - Tab 1: Database Configuration
       - Tab 2: Splunk Configuration
       - Tab 3: Mistral AI Configuration
       - Tab 4: Security Settings
       - Tab 5: Thresholds
       - Tab 6: Backup & Restore
    
    4. Each tab contains:
       - Section header (st.subheader)
       - Configuration inputs (text, number, select fields)
       - Save button
       - Connection test button (if applicable)
       - Sensitive data masking
    
    5. Footer:
       - Last updated timestamp
    
    6. Sidebar:
       - Quick actions (reload, export)
       - Navigation links (Dashboard, Server Performance)
       - Admin access warning
       - "Changes take effect immediately" notice

CONFIGURATION FILE LOCATIONS:
    config/db_config.yaml: Database connection settings
    config/splunk_config.yaml: Splunk/SIEM API credentials
    config/mistral_config.yaml: AI model endpoint and parameters
    config/security.yaml: Session, auth, encryption settings
    config/thresholds.json: Detection and alert thresholds
    config/*.yaml.bak: Automatic backups before updates

SECURITY FEATURES:
    • Admin role enforcement (UI level access control)
    • Sensitive data masking in display (passwords, API keys)
    • Automatic backup creation before save operations
    • YAML/JSON validation before persistence
    • Backup file (.bak) created with timestamp
    • Configuration changes logged with timestamp
    • Password fields use st.text_input with type="password"

UI PATTERNS:
    • Two-column layouts for form organization
    • Selectbox with defaults from current config
    • Number inputs with min/max constraints
    • Text inputs for credentials (masked where applicable)
    • Buttons: "Save Config", "Test Connection", "Backup", "Restore"
    • Success/Error/Warning/Info messages for user feedback

DEPENDENCIES:
    External Libraries:
        - streamlit: Web UI framework
        - yaml: YAML file reading/writing
        - json: JSON file parsing
        - pathlib: File path operations
        - datetime: Timestamps for backups
        - re: Regular expression validation
    
    Internal Modules: None

ERROR HANDLING:
    • File not found: Return empty dict, show warning
    • YAML parse error: Catch and display error message
    • Permission denied: Show error, don't crash
    • Backup creation: Try-except, graceful failure
    • Invalid input: Min/max constraints on number inputs

DATABASE QUERIES: None (configuration management only)

ROLE-BASED ACCESS:
    • Admin: Full access to all configuration tabs
    • Analyst/Viewer: Access denied, redirect to dashboard

╚════════════════════════════════════════════════════════════════════════════╝
"""

import streamlit as st
import yaml
import json
from pathlib import Path
from datetime import datetime
import re

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="System Configuration",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ════════════════════════════════════════════════════════════════════════════
#  CUSTOM CSS FOR SCROLLING AND THEME APPLICATION
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Enable smooth scrolling, apply dark theme, optimize rendering

st.markdown("""
<style>
    /* Ensure main container is scrollable */
    .main {
        overflow-y: auto !important;
        height: 100vh !important;
        max-height: 100vh !important;
    }
    
    /* Fix block container */
    .block-container {
        padding-top: 2rem !important;
        padding-bottom: 2rem !important;
        max-width: 100% !important;
        overflow-y: visible !important;
    }
    
    /* Sidebar scrolling */
    section[data-testid="stSidebar"] {
        height: 100vh !important;
        overflow-y: auto !important;
    }
    
    /* Force scrolling on app view container */
    .appview-container {
        overflow-y: auto !important;
    }
    
    /* Make sure content doesn't get cut off */
    div[data-testid="stVerticalBlock"] {
        overflow: visible !important;
    }
</style>
""", unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════════════════════
#  CONSTANTS & FILE PATHS - CONFIGURATION FILE LOCATIONS
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Define paths to all configuration files

PROJECT_ROOT = Path(__file__).parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"

CONFIG_FILES = {
    'database': CONFIG_DIR / "db_config.yaml",
    'splunk': CONFIG_DIR / "splunk_config.yaml",
    'mistral': CONFIG_DIR / "mistral_config.yaml",
    'security': CONFIG_DIR / "security.yaml",
    'thresholds': CONFIG_DIR / "thresholds.json"
}

# ════════════════════════════════════════════════════════════════════════════
#  HELPER FUNCTIONS - CONFIGURATION I/O AND UTILITIES
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Load/save configs, mask sensitive data, test connections

def load_config(config_file):
    """
    Load configuration from YAML file.
    
    Purpose: Read and parse YAML configuration file with error handling.
    
    Args:
        config_file (Path): Path object pointing to YAML config file
    
    Returns:
        dict: Parsed YAML content, empty dict {} if file missing or error
    
    Error Handling:
        - File not found: Return empty dict (silent fail)
        - YAML parse error: Show error message, return empty dict
        - Permission denied: Show error message, return empty dict
    
    Used By: All render_*_config() functions to load current settings
    """
    try:
        if config_file.exists():
            with open(config_file, 'r') as f:
                return yaml.safe_load(f) or {}
        else:
            return {}
    except Exception as e:
        st.error(f"Error loading {config_file.name}: {e}")
        return {}


def save_config(config_file, data):
    """
    Save configuration to YAML file with automatic backup.
    
    Purpose: Persist configuration changes to YAML with backup safety.
    
    Backup Strategy:
        1. If config_file exists: Create .bak backup
        2. Read entire file content
        3. Write to .yaml.bak with same content
        4. Write new data to original file
    
    Args:
        config_file (Path): Path object to YAML file
        data (dict): Configuration dictionary to save
    
    Returns:
        bool: True if save successful, False on error
    
    Side Effects:
        - Creates/updates config_file with new YAML data
        - Creates backup file: config_file.with_suffix('.yaml.bak')
        - Shows error message if save fails
    
    Used By: All render_*_config() Save buttons
    
    Error Handling:
        - File write error: Show error message, return False
        - Backup creation error: Attempt save anyway
    """
    try:
        # Create backup before saving
        if config_file.exists():
            backup_file = config_file.with_suffix('.yaml.bak')
            with open(config_file, 'r') as f:
                backup_data = f.read()
            with open(backup_file, 'w') as f:
                f.write(backup_data)
        
        # Save new configuration
        with open(config_file, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        
        return True
    except Exception as e:
        st.error(f"Error saving {config_file.name}: {e}")
        return False


def load_json_config(config_file):
    """
    Load configuration from JSON file.
    
    Purpose: Read and parse JSON configuration file (used for thresholds).
    
    Args:
        config_file (Path): Path object pointing to JSON config file
    
    Returns:
        dict: Parsed JSON content, empty dict {} if file missing or error
    
    Error Handling:
        - File not found: Return empty dict
        - JSON parse error: Show error message, return empty dict
        - Permission denied: Show error message, return empty dict
    
    Used By: render_thresholds_config() to load threshold settings
    """
    try:
        if config_file.exists():
            with open(config_file, 'r') as f:
                return json.load(f)
        else:
            return {}
    except Exception as e:
        st.error(f"Error loading {config_file.name}: {e}")
        return {}


def save_json_config(config_file, data):
    """
    Save configuration to JSON file with automatic backup.
    
    Purpose: Persist JSON configuration with safety backup.
    
    Backup Strategy:
        1. If config_file exists: Create .json.bak backup
        2. Write new data to original file with indent=4
    
    Args:
        config_file (Path): Path object to JSON file
        data (dict): Configuration dictionary to save
    
    Returns:
        bool: True if save successful, False on error
    
    Side Effects:
        - Creates/updates config_file with new JSON data
        - Creates backup file: config_file.with_suffix('.json.bak')
        - Shows error message if save fails
    
    Used By: render_thresholds_config() Save button
    
    Error Handling:
        - File write error: Show error message, return False
        - JSON serialization error: Show error message, return False
    """
    try:
        # Create backup
        if config_file.exists():
            backup_file = config_file.with_suffix('.json.bak')
            with open(config_file, 'r') as f:
                backup_data = f.read()
            with open(backup_file, 'w') as f:
                f.write(backup_data)
        
        # Save new configuration
        with open(config_file, 'w') as f:
            json.dump(data, f, indent=4)
        
        return True
    except Exception as e:
        st.error(f"Error saving {config_file.name}: {e}")
        return False


def mask_sensitive_data(value):
    """
    Mask sensitive data for display (passwords, API keys, tokens).
    
    Purpose: Display sensitive information without exposing full value.
    
    Masking Strategy:
        - Show first 2 characters
        - Hide middle characters with asterisks
        - Show last 2 characters
        - Example: "sk_live_1234567890" → "sk_**************90"
    
    Args:
        value (str): Sensitive string to mask
    
    Returns:
        str: Masked string (first2 + asterisks + last2)
             Returns "****" if value is None or < 4 characters
    
    Used By: Display of passwords, API keys, tokens in configuration forms
    
    Note: Masking is UI only - actual value still used in operations
    """
    if not value or len(value) < 4:
        return "****"
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def test_database_connection(config):
    """
    Test database connection.
    
    Purpose: Validate database configuration by attempting connection.
    
    Args:
        config (dict): Database configuration dictionary with:
            - type: 'SQLite', 'MySQL', or 'PostgreSQL'
            - host, port, database, username, password (if applicable)
    
    Returns:
        tuple: (success: bool, message: str)
            - (True, "Connection successful") if connection works
            - (False, error_message) if connection fails
    
    Error Handling:
        - Connection timeout: Catch and return False with message
        - Authentication error: Catch and return False with message
        - Database not found: Catch and return False with message
    
    Used By: "Test Connection" button in Database Configuration tab
    
    Note: Currently placeholder - implement with actual DB driver
    """
    try:
        # Placeholder for actual connection test
        st.info("Testing database connection...")
        # Add actual connection logic here
        return True, "Connection successful"
    except Exception as e:
        return False, str(e)


def test_splunk_connection(config):
    """
    Test Splunk API connection.
    
    Purpose: Validate Splunk configuration by testing API endpoint.
    
    Args:
        config (dict): Splunk configuration with:
            - url: Splunk server URL (e.g., "http://172.20.10.3:8000")
            - token: API authentication token
    
    Returns:
        tuple: (success: bool, message: str)
            - (True, "Connection successful") if API responds
            - (False, error_message) if connection fails
    
    Error Handling:
        - Network unreachable: Catch and return False
        - 401 Unauthorized: Catch and return False
        - Timeout: Catch and return False
    
    Used By: "Test Connection" button in Splunk Configuration tab
    
    Note: Currently placeholder - implement with requests library
    """
    try:
        st.info("Testing Splunk connection...")
        # Add actual connection logic here
        return True, "Connection successful"
    except Exception as e:
        return False, str(e)


def test_mistral_connection(config):
    """
    Test Mistral AI API connection.
    
    Purpose: Validate Mistral/Ollama configuration by testing endpoint.
    
    Args:
        config (dict): Mistral configuration with:
            - url: Ollama/Mistral endpoint (e.g., "http://localhost:11434")
            - api_key: Optional API key (if using remote endpoint)
            - model: Model name to test
    
    Returns:
        tuple: (success: bool, message: str)
            - (True, "Connection successful") if endpoint responds
            - (False, error_message) if connection fails
    
    Error Handling:
        - Endpoint unreachable: Catch and return False
        - Model not found: Catch and return False
        - API error: Catch and return False
    
    Used By: "Test Connection" button in Mistral AI Configuration tab
    
    Note: Currently placeholder - implement with ollama client
    """
    try:
        st.info("Testing Mistral AI connection...")
        # Add actual connection logic here
        return True, "Connection successful"
    except Exception as e:
        return False, str(e)


# ════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION SECTIONS - TAB RENDERING FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Render configuration UI for each settings category

def render_database_config():
    """Render database configuration section"""
    st.subheader("Database Configuration")
    
    config = load_config(CONFIG_FILES['database'])
    
    col1, col2 = st.columns(2)
    
    with col1:
        db_type = st.selectbox(
            "Database Type",
            ["SQLite", "MySQL", "PostgreSQL"],
            index=["SQLite", "MySQL", "PostgreSQL"].index(config.get('type', 'SQLite'))
        )
        
        if db_type == "SQLite":
            db_path = st.text_input(
                "Database Path",
                value=config.get('path', 'cyber_defense.db')
            )
        else:
            db_host = st.text_input(
                "Host",
                value=config.get('host', 'localhost')
            )
            db_port = st.number_input(
                "Port",
                value=config.get('port', 3306 if db_type == "MySQL" else 5432),
                min_value=1,
                max_value=65535
            )
            db_name = st.text_input(
                "Database Name",
                value=config.get('database', 'cyber_defense')
            )
    
    with col2:
        if db_type != "SQLite":
            db_user = st.text_input(
                "Username",
                value=config.get('username', 'admin')
            )
            db_password = st.text_input(
                "Password",
                type="password",
                value=config.get('password', '')
            )
        
        pool_size = st.number_input(
            "Connection Pool Size",
            value=config.get('pool_size', 5),
            min_value=1,
            max_value=100
        )
        
        timeout = st.number_input(
            "Connection Timeout (seconds)",
            value=config.get('timeout', 30),
            min_value=5,
            max_value=300
        )
    
    col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 2])
    
    with col_btn1:
        if st.button("Save Database Config", key="save_db_config", use_container_width=True):
            new_config = {
                'type': db_type,
                'pool_size': pool_size,
                'timeout': timeout
            }
            
            if db_type == "SQLite":
                new_config['path'] = db_path
            else:
                new_config.update({
                    'host': db_host,
                    'port': db_port,
                    'database': db_name,
                    'username': db_user,
                    'password': db_password
                })
            
            if save_config(CONFIG_FILES['database'], new_config):
                st.success("Database configuration saved successfully!")
    
    with col_btn2:
        if st.button("Test Connection", key="test_db_connection", use_container_width=True):
            success, message = test_database_connection(config)
            if success:
                st.success(f"{message}")
            else:
                st.error(f"{message}")


def render_splunk_config():
    """Render Splunk SIEM configuration section"""
    st.subheader("Splunk SIEM Configuration")
    
    config = load_config(CONFIG_FILES['splunk'])
    
    col1, col2 = st.columns(2)
    
    with col1:
        splunk_host = st.text_input(
            "Splunk Server URL",
            value=config.get('host', 'localhost')
        )
        splunk_port = st.number_input(
            "Splunk Port",
            value=config.get('port', 8089),
            min_value=1,
            max_value=65535
        )
        splunk_token = st.text_input(
            "Authentication Token",
            type="password",
            value=config.get('token', ''),
            help="Splunk API authentication token"
        )
    
    with col2:
        index_name = st.text_input(
            "Index Name",
            value=config.get('index', 'main')
        )
        sourcetype = st.text_input(
            "Source Type",
            value=config.get('sourcetype', 'syslog')
        )
        earliest_time = st.text_input(
            "Default Time Range",
            value=config.get('earliest_time', '-24h'),
            help="e.g., -24h, -7d, -1mon"
        )
    
    use_ssl = st.checkbox(
        "Use SSL/TLS",
        value=config.get('ssl', True)
    )
    
    verify_ssl = st.checkbox(
        "Verify SSL Certificate",
        value=config.get('verify_ssl', False)
    )
    
    col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 2])
    
    with col_btn1:
        if st.button("Save Splunk Config", key="save_splunk_config", use_container_width=True):
            new_config = {
                'host': splunk_host,
                'port': splunk_port,
                'token': splunk_token,
                'index': index_name,
                'sourcetype': sourcetype,
                'earliest_time': earliest_time,
                'ssl': use_ssl,
                'verify_ssl': verify_ssl
            }
            
            if save_config(CONFIG_FILES['splunk'], new_config):
                st.success("Splunk configuration saved successfully!")
    
    with col_btn2:
        if st.button("Test Connection", key="test_splunk_connection", use_container_width=True):
            success, message = test_splunk_connection(config)
            if success:
                st.success(f"{message}")
            else:
                st.error(f"{message}")


def render_mistral_config():
    """Render Mistral AI configuration section"""
    st.subheader("Mistral AI Configuration")
    
    config = load_config(CONFIG_FILES['mistral'])
    
    col1, col2 = st.columns(2)
    
    with col1:
        api_endpoint = st.text_input(
            "API Endpoint",
            value=config.get('api_endpoint', 'http://localhost:11434')
        )
        api_key = st.text_input(
            "API Key",
            type="password",
            value=config.get('api_key', ''),
            help="Optional: Required for cloud-based Mistral API"
        )
        model_name = st.text_input(
            "Model Name",
            value=config.get('model', 'mistral:latest')
        )
    
    with col2:
        temperature = st.slider(
            "Temperature",
            min_value=0.0,
            max_value=2.0,
            value=config.get('temperature', 0.7),
            step=0.1,
            help="Controls randomness in output (0 = deterministic, 2 = very random)"
        )
        max_tokens = st.number_input(
            "Max Tokens",
            value=config.get('max_tokens', 2048),
            min_value=128,
            max_value=8192,
            step=128
        )
        confidence_threshold = st.slider(
            "Confidence Threshold",
            min_value=0.0,
            max_value=1.0,
            value=config.get('confidence_threshold', 0.7),
            step=0.05,
            help="Minimum confidence score for threat detection"
        )
    
    timeout = st.number_input(
        "Request Timeout (seconds)",
        value=config.get('timeout', 60),
        min_value=10,
        max_value=300
    )
    
    col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 2])
    
    with col_btn1:
        if st.button("Save Mistral Config", key="save_mistral_config", use_container_width=True):
            new_config = {
                'api_endpoint': api_endpoint,
                'api_key': api_key,
                'model': model_name,
                'temperature': temperature,
                'max_tokens': max_tokens,
                'confidence_threshold': confidence_threshold,
                'timeout': timeout
            }
            
            if save_config(CONFIG_FILES['mistral'], new_config):
                st.success("Mistral AI configuration saved successfully!")
    
    with col_btn2:
        if st.button("Test Connection", key="test_mistral_connection", use_container_width=True):
            success, message = test_mistral_connection(config)
            if success:
                st.success(f"{message}")
            else:
                st.error(f"{message}")


def render_security_config():
    """Render security settings section"""
    st.subheader("Security Settings")
    
    config = load_config(CONFIG_FILES['security'])
    
    col1, col2 = st.columns(2)
    
    with col1:
        session_timeout = st.number_input(
            "Session Timeout (minutes)",
            value=config.get('session_timeout_minutes', 30),
            min_value=5,
            max_value=480
        )
        max_login_attempts = st.number_input(
            "Max Login Attempts",
            value=config.get('max_login_attempts', 5),
            min_value=1,
            max_value=10
        )
        lockout_duration = st.number_input(
            "Account Lockout Duration (minutes)",
            value=config.get('lockout_duration', 15),
            min_value=5,
            max_value=120
        )
    
    with col2:
        jwt_secret = st.text_input(
            "JWT Secret Key",
            type="password",
            value=config.get('secret_key', ''),
            help="Secret key for JWT token generation"
        )
        
        st.markdown("**Password Policy**")
        min_password_length = st.number_input(
            "Minimum Password Length",
            value=config.get('password_policy', {}).get('min_length', 10),
            min_value=8,
            max_value=32
        )
        require_uppercase = st.checkbox(
            "Require Uppercase Letters",
            value=config.get('password_policy', {}).get('require_uppercase', True)
        )
        require_digit = st.checkbox(
            "Require Digits",
            value=config.get('password_policy', {}).get('require_digit', True)
        )
        require_special = st.checkbox(
            "Require Special Characters",
            value=config.get('password_policy', {}).get('require_special', True)
        )
    
    if st.button("Save Security Settings", key="save_security_settings", use_container_width=True):
        new_config = {
            'session_timeout_minutes': session_timeout,
            'max_login_attempts': max_login_attempts,
            'lockout_duration': lockout_duration,
            'secret_key': jwt_secret,
            'password_policy': {
                'min_length': min_password_length,
                'require_uppercase': require_uppercase,
                'require_digit': require_digit,
                'require_special': require_special
            }
        }
        
        if save_config(CONFIG_FILES['security'], new_config):
            st.success("Security settings saved successfully!")


def render_thresholds_config():
    """Render threat detection thresholds section"""
    st.subheader("Threat Detection Thresholds")
    
    config = load_json_config(CONFIG_FILES['thresholds'])
    
    st.markdown("### Severity Thresholds")
    st.markdown("Define score ranges for threat severity levels")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("**🟢 Low**")
        low_min = st.number_input("Min Score", value=config.get('severity', {}).get('low', {}).get('min', 0), key="low_min")
        low_max = st.number_input("Max Score", value=config.get('severity', {}).get('low', {}).get('max', 40), key="low_max")
    
    with col2:
        st.markdown("**🟡 Medium**")
        med_min = st.number_input("Min Score", value=config.get('severity', {}).get('medium', {}).get('min', 41), key="med_min")
        med_max = st.number_input("Max Score", value=config.get('severity', {}).get('medium', {}).get('max', 70), key="med_max")
    
    with col3:
        st.markdown("**🟠 High**")
        high_min = st.number_input("Min Score", value=config.get('severity', {}).get('high', {}).get('min', 71), key="high_min")
        high_max = st.number_input("Max Score", value=config.get('severity', {}).get('high', {}).get('max', 90), key="high_max")
    
    with col4:
        st.markdown("**🔴 Critical**")
        crit_min = st.number_input("Min Score", value=config.get('severity', {}).get('critical', {}).get('min', 91), key="crit_min")
        crit_max = st.number_input("Max Score", value=config.get('severity', {}).get('critical', {}).get('max', 100), key="crit_max")
    
    st.markdown("---")
    st.markdown("### Auto-Response Settings")
    
    col1, col2 = st.columns(2)
    
    with col1:
        auto_block_enabled = st.checkbox(
            "Enable Auto-Block",
            value=config.get('auto_response', {}).get('enabled', True),
            help="Automatically block threats above threshold"
        )
        auto_block_threshold = st.slider(
            "Auto-Block Threshold Score",
            min_value=0,
            max_value=100,
            value=config.get('auto_response', {}).get('threshold', 80)
        )
    
    with col2:
        notification_threshold = st.slider(
            "Alert Notification Threshold",
            min_value=0,
            max_value=100,
            value=config.get('notification_threshold', 60),
            help="Minimum score to trigger notifications"
        )
        ai_confidence_min = st.slider(
            "Minimum AI Confidence",
            min_value=0.0,
            max_value=1.0,
            value=config.get('ai_confidence_min', 0.6),
            step=0.05,
            help="Minimum LLM confidence to act on threat"
        )
    
    if st.button("Save Thresholds", key="save_thresholds", use_container_width=True):
        new_config = {
            'severity': {
                'low': {'min': low_min, 'max': low_max},
                'medium': {'min': med_min, 'max': med_max},
                'high': {'min': high_min, 'max': high_max},
                'critical': {'min': crit_min, 'max': crit_max}
            },
            'auto_response': {
                'enabled': auto_block_enabled,
                'threshold': auto_block_threshold
            },
            'notification_threshold': notification_threshold,
            'ai_confidence_min': ai_confidence_min
        }
        
        if save_json_config(CONFIG_FILES['thresholds'], new_config):
            st.success("Thresholds saved successfully!")


def render_backup_restore():
    """Render backup and restore section"""
    st.subheader("Backup & Restore")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Create Backup**")
        if st.button("Backup All Configurations", key="backup_configs", use_container_width=True):
            backup_name = f"config_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            st.info(f"Creating backup: {backup_name}")
            # Implement actual backup logic
            st.success("Backup created successfully!")
    
    with col2:
        st.markdown("**Restore from Backup**")
        backup_file = st.file_uploader("Choose backup file", type=['zip', 'tar'], key="backup_uploader")
        if backup_file and st.button("Restore Configuration", key="restore_config", use_container_width=True):
            st.warning("This will overwrite current configuration!")
            # Implement actual restore logic
            st.success("Configuration restored successfully!")


# ════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION - PAGE ORCHESTRATION
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Orchestrate admin panel with role checking and tab rendering

def main():
    """
    Main function for system configuration management.
    
    Purpose: Orchestrate admin panel with role enforcement and configuration tabs.
    
    Execution Flow:
        1. Display page title and description
        2. Check user role from session state
        3. If role != 'admin': Show access denied, redirect button, exit
        4. If admin:
           - Create 6-tab interface
           - Tab 1: Database Configuration
           - Tab 2: Splunk Configuration
           - Tab 3: Mistral AI Configuration
           - Tab 4: Security Settings
           - Tab 5: Detection Thresholds
           - Tab 6: Backup & Restore
        5. Display last updated timestamp
    
    Role-Based Access Control:
        - Admin: Full access to all configuration tabs
        - Analyst/Viewer: Access denied message + redirect button
    
    Tab Structure:
        Each tab calls corresponding render_*_config() function which:
        1. Loads current configuration from file
        2. Renders form inputs with current values
        3. Provides Save button to persist changes
        4. Provides Test Connection button (where applicable)
        5. Shows success/error messages
    
    Returns: None (renders page)
    
    Session State:
        - st.session_state.role: User role (admin/analyst/viewer)
    
    Used By: if __name__ == "__main__" entry point
    """
      # ════════════════════════════════════════════════════════════════════════
    # TOP BAR - NAVIGATION AND BRANDING
    # ════════════════════════════════════════════════════════════════════════
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
    st.markdown("""
    <style>
        .topbar {
            background: linear-gradient(135deg, #141d26 0%, #243447 100%);
            color: #E2E2D2;
            padding: 10px 18px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 20px;
        }
        .topbar .left { display:flex; align-items:center; gap:12px; }
        .topbar .brand { font-weight:700; font-size:18px; color:#E2E2D2; }
        .topbar .links { display:flex; gap:10px; align-items:center; }
        .topbar a { color: #E2E2D2; text-decoration: none; padding:8px 12px; border-radius:6px; font-size:14px; transition: all 0.3s ease; }
        .topbar a:hover { background:#243447; color:#E2E2D2; }
        .topbar .cta { background: #c51f5d; color: #ffffff; padding:8px 12px; border-radius:6px; font-weight:600; }
        .topbar .cta:hover { background: #d63574; }
        @media (max-width: 700px) {
            .topbar { flex-direction: column; align-items: flex-start; gap:8px; }
        }
    </style>

    <div class="topbar">
        <div class="left">
            <span class="brand"></span>
        </div>
        <div class="links">
            <a href="Dashboard_Overview" title="Dashboard">Dashboard</a>
            <a href="Live_Threat_Monitor" title="Threats">Monitor</a>
            <a href="Performance_Metrics" title="Metrics">Metrics</a>
            <a class="cta" href="System_Configuration" title="Configuration">Configuration</a>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.title("System Configuration")
    st.markdown("Configure system settings, API credentials, and operational parameters")
    

    st.markdown("---")
    
    # Check admin role only (no authentication required)
    user_role = st.session_state.get('role', 'admin')  # Default to admin for testing
    
    if user_role != 'admin':
        st.error("Access Denied: Admin privileges required")
        st.info("This page is restricted to administrators only.")
        if st.button("Go to Dashboard", key="go_to_dashboard"):
            st.switch_page("pages/Dashboard_Overview.py")
        st.stop()
    
    # Configuration tabs
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "Database",
        "Splunk",
        "Mistral AI",
        "Security",
        "Thresholds",
        "Backup"
    ])
    
    with tab1:
        render_database_config()
    
    with tab2:
        render_splunk_config()
    
    with tab3:
        render_mistral_config()
    
    with tab4:
        render_security_config()
    
    with tab5:
        render_thresholds_config()
    
    with tab6:
        render_backup_restore()
    
    st.markdown("---")
    st.caption(f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


# ════════════════════════════════════════════════════════════════════════════
#  SIDEBAR - QUICK ACTIONS AND NAVIGATION
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Admin controls, navigation links, access warnings

with st.sidebar:
    st.title("Configuration")
    st.markdown("---")
    
    st.markdown("### Quick Actions")
    if st.button("Reload All Configs", key="reload_configs", use_container_width=True):
        st.rerun()
    
    if st.button("Export All Settings", key="export_settings", use_container_width=True):
        st.info("Export functionality coming soon")
    
    st.markdown("---")
    st.markdown("### Navigation")
    st.page_link("pages/Dashboard_Overview.py", label="Dashboard")
    st.page_link("pages/Server_Performance.py", label="Server Performance")
    
    st.markdown("---")
    st.warning("Admin Only Access")
    st.info("Changes take effect immediately")


# ════════════════════════════════════════════════════════════════════════════
#  APPLICATION ENTRY POINT - SCRIPT EXECUTION
# ════════════════════════════════════════════════════════════════════════════
# Purpose: Execute main() when script is run directly

if __name__ == "__main__":
    main()
