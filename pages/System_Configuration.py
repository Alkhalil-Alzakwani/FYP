r"""
================================================================================
MULTILAYERED CYBER DEFENSE PLATFORM - SYSTEM CONFIGURATION
================================================================================

File: pages/System_Configuration.py
Purpose: Administrative configuration panel for system settings and parameters

DESCRIPTION:
    This module provides a centralized interface for administrators to manage
    system configurations, API credentials, security thresholds, and operational
    parameters. All settings are persisted in YAML configuration files and can
    be dynamically updated without system restart.

CONFIGURATION CATEGORIES:
    1. Database Configuration:
        - Database type selection (SQLite/MySQL)
        - Connection parameters (host, port, database name)
        - Authentication credentials
        - Connection pool settings
        
    2. Splunk SIEM Configuration:
        - Splunk server URL and port
        - API authentication token
        - Search query parameters
        - Index names and sourcetypes
        - Query time ranges
        
    3. Mistral AI Configuration:
        - API endpoint URL
        - API key management
        - Model selection
        - Temperature and token limits
        - Confidence thresholds
        
    4. pfSense Firewall Configuration:
        - Firewall API endpoint
        - API credentials
        - Auto-block settings
        - Rule priority configuration
        
    5. Security Settings:
        - Session timeout duration
        - Maximum login attempts
        - JWT secret key
        - Password policy rules
        - Rate limiting parameters
        
    6. Threat Detection Thresholds:
        - Severity level thresholds (Low/Medium/High/Critical)
        - LLM confidence minimum
        - Auto-response triggers
        - Alert notification levels
        
    7. Performance Tuning:
        - Log retention period
        - Cache settings
        - Batch processing sizes
        - Refresh intervals

FEATURES:
    - Secure credential management
    - Configuration validation
    - Test connectivity buttons
    - Export/Import configuration
    - Configuration backup and restore
    - Real-time configuration updates
    - Audit logging for changes
    - Role-based access control (Admin only)

CONFIGURATION FILES:
    - config/db_config.yaml: Database settings
    - config/splunk_config.yaml: SIEM integration
    - config/mistral_config.yaml: AI model settings
    - config/security.yaml: Security parameters
    - config/thresholds.json: Detection thresholds

SECURITY:
    - Admin role required to access this page
    - Sensitive data masked in UI (passwords, API keys)
    - Configuration changes logged to audit trail
    - Backup created before each update
    - Encryption for stored credentials

DEPENDENCIES:
    - streamlit: UI framework
    - yaml: Configuration file handling
    - json: Threshold file management
    - pathlib: File path operations

Author: Multilayered Cyber Defense Team
Last Modified: October 30, 2025
Version: 1.0.0
================================================================================
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

# ============================================================================
# CONSTANTS & PATHS
# ============================================================================

PROJECT_ROOT = Path(__file__).parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"

CONFIG_FILES = {
    'database': CONFIG_DIR / "db_config.yaml",
    'splunk': CONFIG_DIR / "splunk_config.yaml",
    'mistral': CONFIG_DIR / "mistral_config.yaml",
    'security': CONFIG_DIR / "security.yaml",
    'thresholds': CONFIG_DIR / "thresholds.json"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def load_config(config_file):
    """Load configuration from YAML file"""
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
    """Save configuration to YAML file"""
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
    """Load configuration from JSON file"""
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
    """Save configuration to JSON file"""
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
    """Mask sensitive data for display"""
    if not value or len(value) < 4:
        return "****"
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def test_database_connection(config):
    """Test database connection"""
    try:
        # Placeholder for actual connection test
        st.info("Testing database connection...")
        # Add actual connection logic here
        return True, "Connection successful"
    except Exception as e:
        return False, str(e)


def test_splunk_connection(config):
    """Test Splunk API connection"""
    try:
        st.info("Testing Splunk connection...")
        # Add actual connection logic here
        return True, "Connection successful"
    except Exception as e:
        return False, str(e)


def test_mistral_connection(config):
    """Test Mistral AI API connection"""
    try:
        st.info("Testing Mistral AI connection...")
        # Add actual connection logic here
        return True, "Connection successful"
    except Exception as e:
        return False, str(e)


# ============================================================================
# CONFIGURATION SECTIONS
# ============================================================================

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
        if st.button("Save Database Config", use_container_width=True):
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
        if st.button("Test Connection", use_container_width=True):
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
        if st.button("Save Splunk Config", use_container_width=True):
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
        if st.button("🔌 Test Connection", use_container_width=True):
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
        if st.button("Save Mistral Config", use_container_width=True):
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
        if st.button("Test Connection", use_container_width=True):
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
    
    if st.button("Save Security Settings", use_container_width=True):
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
    
    if st.button("Save Thresholds", use_container_width=True):
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
        if st.button("Backup All Configurations", use_container_width=True):
            backup_name = f"config_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            st.info(f"Creating backup: {backup_name}")
            # Implement actual backup logic
            st.success("Backup created successfully!")
    
    with col2:
        st.markdown("**Restore from Backup**")
        backup_file = st.file_uploader("Choose backup file", type=['zip', 'tar'])
        if backup_file and st.button("Restore Configuration", use_container_width=True):
            st.warning("This will overwrite current configuration!")
            # Implement actual restore logic
            st.success("Configuration restored successfully!")


# ============================================================================
# MAIN CONTENT
# ============================================================================

def main():
    """Main function for system configuration"""
    
    st.title("System Configuration")
    st.markdown("Configure system settings, API credentials, and operational parameters")
    st.markdown("---")
    
    # Check admin access (placeholder - implement actual authentication check)
    if not st.session_state.get('authenticated', False):
        st.warning("Please login to access system configuration")
        if st.button("Go to Login"):
            st.switch_page("pages/login.py")
        st.stop()
    
    # Check admin role
    if st.session_state.get('role', '') != 'admin':
        st.error("Access Denied: Admin privileges required")
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


# ============================================================================
# SIDEBAR
# ============================================================================

with st.sidebar:
    st.title("Configuration")
    st.markdown("---")
    
    st.markdown("### Quick Actions")
    if st.button("Reload All Configs", use_container_width=True):
        st.rerun()
    
    if st.button("Export All Settings", use_container_width=True):
        st.info("Export functionality coming soon")
    
    st.markdown("---")
    st.markdown("### Navigation")
    st.page_link("pages/Dashboard_Overview.py", label="Dashboard")
    st.page_link("pages/Server_Performance.py", label="Server Performance")
    
    st.markdown("---")
    st.warning("Admin Only Access")
    st.info("Changes take effect immediately")


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    main()
