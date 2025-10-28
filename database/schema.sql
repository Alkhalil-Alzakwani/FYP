-- ============================================================================
-- CYBER DEFENSE PLATFORM DATABASE SCHEMA
-- ============================================================================

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    role TEXT NOT NULL DEFAULT 'viewer',
    last_login TEXT,
    created_at TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    CONSTRAINT check_role CHECK (role IN ('admin', 'analyst', 'viewer'))
);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Firewall logs table
CREATE TABLE IF NOT EXISTS firewall_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT NOT NULL,
    dest_ip TEXT NOT NULL,
    action TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    protocol TEXT,
    rule_id TEXT
);

-- IDS alerts table
CREATE TABLE IF NOT EXISTS ids_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    signature TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dest_ip TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

-- SIEM logs table
CREATE TABLE IF NOT EXISTS siem_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    message TEXT,
    threat_score INTEGER,
    timestamp TEXT NOT NULL
);

-- Threat scores table
CREATE TABLE IF NOT EXISTS threat_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    category TEXT,
    ai_context TEXT,
    timestamp TEXT NOT NULL
);

-- Performance metrics table
CREATE TABLE IF NOT EXISTS performance_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    metric_name TEXT NOT NULL,
    value REAL NOT NULL,
    date TEXT NOT NULL
);

-- Threat intelligence feeds table
CREATE TABLE IF NOT EXISTS threat_intel_feeds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT NOT NULL,
    type TEXT NOT NULL,
    reputation INTEGER,
    last_seen TEXT
);

-- System configuration table
CREATE TABLE IF NOT EXISTS system_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parameter TEXT UNIQUE NOT NULL,
    value TEXT NOT NULL
);
