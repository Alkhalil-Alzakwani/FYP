# Multilayered Cyber Defense Platform Dashboard Documentation

## 1. Overall Architecture

### Purpose

The Streamlit Dashboard serves as the central command and visualization interface for the multilayered cyber defense system. It integrates the following components:

- **Firewall logs** (pfSense)
- **IDS/IPS alerts** (Snort/Suricata)
- **SIEM analytics** (Splunk)
- **Threat intelligence feeds** (External IOC sources)
- **LLM (Mistral:latest)** for contextual phishing analysis
- **SQLite database** for persistence, scoring, and performance tracking
- **Real-time threat geolocation** (GeoIP-based threat map)
- **Performance metrics tracking** (KPI analytics)

---

## 2. Project Directory Structure

```
FYP-Project/
│
├── app.py                                # Main introductory landing page
│
├── auth/
│   ├── auth_manager.py                   # Core authentication logic (login, logout, session)
│   ├── password_utils.py                 # Password hashing and validation (bcrypt)
│   └── session_manager.py                # Streamlit session state handler
|
├── pages/
│   ├── login.py                          # User authentication page
│   ├── Dashboard_Overview.py             # Main metrics and summary
│   ├── Live_Threat_Monitor.py            # Real-time Splunk log stream
│   ├── AI_Log_Analysis.py                # Mistral LLM analysis page
│   ├── Threat_Scoring.py                 # Threat scoring algorithms
│   ├── Performance_Metrics.py            # KPI tracking and reports
│   ├── Server_Performance.py             # Real-time server resource monitoring
│   ├── System_Configuration.py           # API keys, DB setup, thresholds
│   ├── Forensics_And_Reports.py          # Incident reports and exports
│   └── User_Management.py                # Admin page for managing user accounts
│
├── config/
│   ├── db_config.yaml                    # Database connection info
│   ├── splunk_config.yaml                # Splunk connection & query params
│   ├── mistral_config.yaml               # LLM model config
│   ├── thresholds.json                   # Detection & severity limits
│   └── security.yaml                     # JWT secret key and session timeout configs
|
├── database/
│   ├── schema.sql                        # SQL schema definition
│   ├── init_db.py                        # Script to initialize tables
│   ├── queries.py                        # Reusable SQL queries
│   └── seed_users.py                        # Script to create initial admin user
│
├── models/
│   ├── threat_scorer.py                  # Threat scoring engine
│   ├── performance_metrics.py            # KPI formulas
│   ├── mistral_analyzer.py               # Mistral log analyzer wrapper
│   ├── auto_response.py                  # Automated API response (pfSense)
│   └── utils.py                          # Helper functions
│
├── data/
│   ├── sample_logs.csv                   # Example logs for testing
│   ├── attack_simulation_results.csv     # Test data (GoPhish/SET)
│   └── threat_feeds.csv                  # External threat feed samples
│
├── assets/
│   ├── logo.png
│   └── style.css
│
├── requirements.txt
└── README.md
```

---

3. Database Schema

| Table               | Purpose                       | Key Fields                                                |
| ------------------- | ----------------------------- | --------------------------------------------------------- |
| firewall_logs       | Stores pfSense firewall data  | id, src_ip, dest_ip, action, timestamp, protocol, rule_id |
| ids_alerts          | Stores Suricata/Snort alerts  | id, signature, severity, src_ip, dest_ip, timestamp       |
| siem_logs           | Stores aggregated Splunk data | id, source, event_type, message, threat_score, timestamp  |
| threat_scores       | Stores computed threat scores | id, event_id, score, severity, category, ai_context       |
| performance_metrics | KPI tracking                  | id, metric_name, value, date                              |
| threat_intel_feeds  | Stores IOC feed data          | id, indicator, type, reputation, last_seen                |
| system_config       | Stores system parameters      | id, parameter, value                                      |

---
3.1. Database Schema Additions

Table: users

| Field         | Type                             | Description                  |
| ------------- | -------------------------------- | ---------------------------- |
| id            | INT (PK, AUTO_INCREMENT)         | Unique user ID               |
| username      | VARCHAR(50)                      | Unique login name            |
| email         | VARCHAR(100)                     | Optional user email          |
| password_hash | VARCHAR(255)                     | Hashed password using bcrypt |
| role          | ENUM('admin','analyst','viewer') | Access level                 |
| last_login    | DATETIME                         | Last login timestamp         |
| created_at    | DATETIME                         | Account creation timestamp   |
| active        | BOOLEAN                          | Account activation flag      |

Table: sessions

| Field      | Type                | Description          |
| ---------- | ------------------- | -------------------- |
| session_id | VARCHAR(64) (PK)    | Unique session token |
| user_id    | INT (FK → users.id) | Associated user      |
| created_at | DATETIME            | Session start time   |
| expires_at | DATETIME            | Expiry time          |
| ip_address | VARCHAR(45)         | User IP              |
| user_agent | VARCHAR(255)        | Browser fingerprint  |

---

4. Data Flows and Linkages

| Source         | Data Type                      | Linked To       | Function                                                  |
| -------------- | ------------------------------ | --------------- | --------------------------------------------------------- |
| pfSense        | Firewall Logs (via syslog/CSV) | firewall_logs   | Used for traffic blocking and rule-based analysis         |
| Suricata/Snort | IDS Alerts                     | ids_alerts      | Phishing pattern detection                                |
| Splunk         | SIEM Events                    | siem_logs       | Aggregates logs and forwards to Mistral and threat scorer |
| Mistral        | Text analysis API              | threat_scores   | Extracts threat context and predicts phishing intent      |
| SQL DB         | Central Storage                | All modules     | Consolidates metrics, scores, and analytics               |
| Streamlit      | Dashboard                      | All data layers | Visualization and management                              |

---
Authentication Workflow
Login Process (pages/login.py)

User opens the dashboard (app.py) → introductory page with platform overview.

User clicks "Go to Login" button → redirected to login page (pages/login.py).

User enters credentials.

Credentials are verified using auth_manager.py.

If valid, a secure session is created in session_manager.py.

User is redirected to the main dashboard (Dashboard_Overview.py).

Logout Process

User clicks “Logout” → session invalidated → redirected to login page.

Access Control

Each Streamlit page checks user role before rendering:

if st.session_state.get("role") not in ["admin", "analyst"]:
    st.error("Access Denied.")
    st.stop()

---
Security Configuration (config/security.yaml)

Example content:

secret_key: "replace_with_strong_secret_key"
session_timeout_minutes: 30
password_policy:
  min_length: 10
  require_uppercase: true
  require_digit: true
  require_special: true
---

5. Streamlit Pages and Their Functionality

**Home Page** (`app.py`)

**Purpose:** Introductory landing page
**Features:**

* Platform overview and key features
* Quick statistics and metrics
* Technology stack information
* Getting started guide with navigation to login
* Sidebar with navigation and quick links
  **Data source:** Static content

---

**Login Page** (`pages/login.py`)

**Purpose:** User authentication
**Features:**

* Username and password input fields
* Secure login with session creation
* Rate limiting (5 failed attempts = account lock)
* Password validation and error messages
* Redirect to Dashboard Overview on success
  **Data source:** users table, sessions table

---

1. Dashboard Overview (`pages/Dashboard_Overview.py`)

**Purpose:** Executive summary view
**Features:**

* Total attacks detected (real-time counter)
* Detection Rate, Prevention Rate, False Positive Rate
* Recent top 10 phishing events
* Threat map (by source country using GeoIP)
* Charts: Attack types, severity distribution
  **Data source:** performance_metrics, threat_scores, Splunk logs

---

2. Live Threat Monitor (`pages/Live_Threat_Monitor.py`)

**Purpose:** Stream real-time logs from Splunk API
**Features:**

* Live updating data table (auto-refresh every 10 seconds)
* Filters by source, severity, type
* Color-coded severity badges
* Option to block IP via pfSense API
  **Linked to:** Splunk REST API (localhost:8000), pfSense API

---

3. AI Log Analysis (`pages/AI_Log_Analysis.py`)

**Purpose:** Use Mistral LLM for context-aware log analysis
**Features:**

* Input field for log text or batch upload
* “Analyze with Mistral” button returns:

  * Phishing likelihood (0–1)
  * Summary of suspicious behavior
  * Suggested response action
* Results stored in `threat_scores`
  **Mathematical Formula:**

Threat_Score = (LLM_Confidence × 0.6) + (Severity_Weight × 0.3) + (Reputation_Penalty × 0.1)

---

4. Threat Scoring (`pages/Threat_Scoring.py`)

**Purpose:** Implement the threat scoring engine
**Algorithm Components:**

1. Severity Weight (Sw): Based on alert type
2. Frequency Weight (Fw): Number of repeated incidents from same IP
3. Reputation Weight (Rw): From threat feeds
4. AI Confidence (Aic): From Mistral output

**Final Formula:**

Final_Score = (Sw × 0.4) + (Fw × 0.2) + (Rw × 0.1) + (Aic × 0.3)

**Output Categories:**

* Low (0–40)
* Medium (41–70)
* High (71–100)

Automatic blocking is triggered for High category.

---

### 5. Performance Metrics (`pages/Performance_Metrics.py`)

**Purpose:** Track detection and prevention KPIs
**Features:**
- Real-time KPI dashboard with 6 key metrics
- Interactive performance analytics
- Trend analysis and historical comparison
- No emojis; dark-themed UI matching project design

**KPIs Calculated:**
- **Detection Rate** = Detected threats / Total logs
- **Prevention Rate** = Blocked threats / Total threats
- **False Positive Rate** = False positives / (True positives + False positives)
- **MTTD** (Mean Time to Detect) = Average time from event timestamp to indexing
- **MTTR** (Mean Time to Respond) = Average response time (simulated)
- **Auto-Containment Rate** = Auto-blocked incidents / Total incidents

**Key Functions:**
- `get_detection_rate()` – Calculates detection efficiency
- `get_prevention_rate()` – Tracks blocking effectiveness
- `get_false_positive_rate()` – Measures alert accuracy
- `get_mean_time_to_detect()` – MTTD from log timestamps
- `get_auto_containment_rate()` – Auto-blocking success rate
- `get_detection_rate_over_time()` – 30-day trend analysis
- `get_severity_response_time()` – Severity vs. response correlation

**Graphs:**
- **Line chart:** Detection Rate trend (last 30 days)
- **Bar chart:** Auto-containment vs. manual intervention
- **Scatter plot:** Severity level vs. response time (color-coded by severity)

**Data Source:** `splunk_logs` table, `performance_metrics` table
**UI Components:** 6-column metric grid, 2-column chart layout, responsive design

---

### 6. Live Threat Monitor (`pages/Live_Threat_Monitor.py`)

**Purpose:** Stream real-time logs from Splunk API with geolocation threat mapping
**Features:**
- **Real-time log filtering** (severity, host, source, search text)
- **Pagination** (configurable logs per page: 10–500)
- **Expandable log details** with 3-column layout
- **Color-coded severity badges** (critical, high, medium, low, info)
- **Threat geolocation map** (Oman-focused, PyDeck-based)
- **Severity assessment** with contextual reasons
- **Event data visualization** (JSON embedded)
- **AI analysis button** (links to AI_Log_Analysis.py)
- **Sourcetype statistics** table
- **Auto-refresh capability**

**Key Functions:**
- `get_unique_hosts()` – Fetches distinct hosts from logs
- `get_unique_sources()` – Fetches distinct sources from logs
- `get_sourcetype_stats()` – Distribution of log types
- `extract_ip_from_text()` – Regex-based IP extraction
- `is_valid_ip()` – IPv4 validation with octet range checking
- `geolocate_ip()` – GeoIP lookup via ipapi.co with private IP fallback
- `build_attack_points()` – Creates map markers from logs (50 limit for performance)
- `fetch_and_store_logs()` – Splunk API integration

**Threat Map:**
- **Center:** Oman (lat 21.5°, lon 57.0°)
- **Zoom:** 4.8 (regional view)
- **Data:** Geolocated IPs with color-coded severity
- **Tooltips:** IP, country, source, severity
- **Private IPs:** Mapped to Oman center as fallback

**Database Queries:**
- Splunk logs by severity, source, search text
- Host and source filtering
- Severity-based sorting (ascending/descending)

**Data Source:** Splunk REST API, `splunk_logs` table
**API Integration:** Splunk at 172.20.10.3:8000

---

### 7. Server Performance (`pages/Server_Performance.py`)

**Purpose:** Real-time server resource monitoring
**Features:**
- **CPU Monitoring:** Overall utilization and per-core breakdown
- **Memory Tracking:** RAM usage, swap memory, percentage
- **Disk Analytics:** Space per partition, I/O statistics
- **Network Monitoring:** Bytes sent/received, active interfaces
- **GPU Metrics:** If available on system
- **Top Processes:** CPU-intensive process list
- **System Info:** OS, uptime, boot time
- **Alert Thresholds:** High usage warnings
- **Auto-refresh:** Configurable interval (5–60 seconds)
- **Interactive Visualizations:** Gauge charts, bar charts, pie charts, line graphs

**Data Source:** `psutil` (real-time system metrics)
**Visualizations:** Plotly gauge charts, bar charts, pie charts, area charts
**UI Design:** Dark theme matching project standard, responsive grid layout


---

### 8. AI Log Analysis (`pages/AI_Log_Analysis.py`)

**Purpose:** Use Mistral LLM for context-aware log analysis
**Features:**
- **Log selection** by source or manual input
- **Batch analysis** of multiple logs
- **LLM processing** via Ollama (Mistral model)
- **Threat scoring** extraction from AI output
- **Historical context** storage in threat_scores table
- **Error handling** for missing Ollama service
- **GPU acceleration** optional via `use_gpu` parameter

**Key Functions:**
- `get_logs_by_source()` – Fetch logs from specified source
- `get_unique_sources()` – List available log sources
- `call_mistral()` – Make Mistral API call via Ollama
- `parse_ollama_response()` – Extract JSON from stream response
- `extract_threat_score()` – Parse confidence score from analysis
- `save_threat_score()` – Store results in threat_scores table
- `analyze_logs_batch()` – Process multiple logs with progress tracking

**Prompting Strategy:**
- Context-aware LLM prompt requesting JSON output
- Extracts phishing likelihood, behavior summary, suggested response
- Validates JSON parsing with fallback text extraction

**AI Output Format:**
```json
{
  "confidence": 0.85,
  "summary": "Suspicious email with credential harvesting",
  "action": "Block sender and quarantine"
}
```

**Database Integration:**
- Stores results in `threat_scores` table
- Links to `splunk_logs` by source
- Used by Threat_Scoring.py for final scoring

**Ollama Integration:**
- Default model: `mistral:latest`
- Default host: `localhost:11434`
- Fallback: ChatGPT simulation for testing
- GPU support: Configurable

---

### 9. Threat Scoring (`pages/Threat_Scoring.py`)

**Purpose:** Implement multi-factor threat scoring engine
**Features:**
- **4-factor scoring algorithm** (Severity, Frequency, Reputation, AI Confidence)
- **Automated blocking** for high-severity threats
- **pfSense API integration** for IP blocking
- **Block history tracking**
- **Source-based classification** (sources, hosts, IPs)
- **Manual and automatic responses**

**Threat Scoring Algorithm:**

```
Final_Score = (Sw × 0.4) + (Fw × 0.2) + (Rw × 0.1) + (Aic × 0.3)

Where:
  Sw  = Severity Weight (0–10)
  Fw  = Frequency Weight (0–10)
  Rw  = Reputation Weight (0–10)
  Aic = AI Confidence Weight (0–10)
```

**Severity Weights:**
- Critical: 10
- High: 8
- Medium: 5
- Low: 2
- Info: 1

**Frequency Calculation:**
```
Fw = min(incident_count / 10, 10)
```
(Capped at 10 to prevent over-weighting)

**Reputation Weight:**
- Fetched from `threat_intel_feeds` table
- Range: 0–10 (higher = more malicious)

**AI Confidence Weight:**
- From Mistral analysis (0–1 scale)
- Normalized to 0–10

**Score Classification:**
- **Low** (0–40): Monitor only
- **Medium** (41–70): Alert analyst
- **High** (71–100): Auto-block triggered

**Key Functions:**
- `severity_to_weight()` – Map severity string to numeric weight
- `frequency_weight()` – Calculate incident frequency score
- `get_reputation_for_indicator()` – Fetch threat feed reputation
- `get_latest_ai_confidence_for_source()` – Get latest AI score
- `compute_final_score()` – Calculate weighted final score
- `classify_score()` – Categorize score into threat level
- `try_block_ip_via_pfsense()` – Attempt IP blocking via API
- `record_block_action()` – Log blocking attempt

**pfSense Integration:**
- API endpoint: Configurable in `system_config`
- Methods: Local database or pfSense REST API
- Rollback: Automatic on API failure

**Data Source:** `splunk_logs`, `threat_intel_feeds`, `threat_scores`
**UI Components:** Source/host selector, manual scoring override, block history table

---

### 10. Dashboard Overview (`pages/Dashboard_Overview.py`)

**Purpose:** Executive summary with real-time KPIs and threat visualization
**Features:**
- **Real-time metrics:** Total attacks, high-severity count, blocked connections
- **Detection/Prevention KPIs:** Calculated in real-time
- **Threat distribution charts:** Type and severity breakdowns
- **Recent threats table:** Last 10 incidents with expandable details
- **Performance metrics:** Detection rate, prevention rate, FP rate
- **Quick navigation panel:** Links to all major pages
- **Responsive UI:** Dark theme with gradient cards

**Key Functions:**
- `get_total_attacks()` – Count all splunk logs
- `get_high_severity_threats()` – Critical/high severity count
- `get_blocked_connections()` – Count critical severity logs
- `get_recent_threats()` – Last N incidents with context
- `get_threat_distribution()` – Severity distribution
- `get_attack_types()` – Sourcetype breakdown
- `calculate_detection_rate()` – Real-time KPI
- `calculate_prevention_rate()` – Real-time KPI
- `calculate_false_positive_rate()` – Real-time KPI

**Visualizations:**
- **Pie chart:** Threat severity distribution
- **Bar chart:** Attack types by count
- **Table:** Recent threats with sortable columns
- **Metric cards:** 6-column KPI grid

**Data Source:** `splunk_logs`, performance metrics
**Refresh Rate:** On-demand (user clicks, page loads)

---

### 11. Threat Scoring Details (`pages/Threat_Scoring.py`)

**UI Sections:**
- **Scoring Dashboard:** Real-time score display
- **Manual Override:** Allow analyst to adjust scores
- **Block History:** Log of all blocking actions
- **Source Statistics:** High-risk sources ranking
- **Frequency Analysis:** Incident count by source (30-day window)

**Database Queries:**
- Aggregate logs by source/host
- Calculate incident frequency
- Fetch threat intelligence scores
- Retrieve AI confidence scores
- Log blocking actions with timestamp and reason

---

### 12. System Configuration (`pages/System_Configuration.py`)

**Purpose:** Administrative configuration panel
**Features:**
- Set thresholds for severity and LLM confidence
- Manage API keys for Splunk and pfSense
- Configure database connection credentials
- Enable or disable Auto-block feature
- View current system status
- Test connectivity to external services

**Configurable Parameters:**
- Splunk API URL, username, password
- pfSense API endpoint, auth token
- LLM model settings (Ollama host, model name)
- Threat score thresholds
- Auto-block toggle
- Session timeout duration

**Data Source:** `system_config` table
**Access Control:** Admin-only

---

### 13. Forensics and Reports (`pages/Forensics_And_Reports.py`)

**Purpose:** Post-incident forensic analysis and reporting
**Features:**
- Generate downloadable incident reports (PDF or CSV)
- Display raw Splunk event data
- Visualize incident timeline
- Export performance summaries
- Incident severity heat map
- Source attribution analysis

**Report Sections:**
- Executive summary
- Timeline of events
- Affected hosts and sources
- Threat scores and classifications
- Recommended actions
- Historical context

**Data Source:** `splunk_logs`, `threat_scores`, `performance_metrics`
**Export Formats:** PDF, CSV, JSON

---

### 14. User Management (`pages/User_Management.py`)

**Purpose:** Admin page for managing user accounts
**Features:**
- **User listing:** All users with role and status
- **Create user:** Add new user with role assignment
- **Edit user:** Update user details
- **Reset password:** Force password reset
- **Deactivate/Activate:** Toggle account status
- **Delete user:** Remove user from system
- **Role management:** Admin, analyst, viewer roles
- **Activity logging:** Track user actions

**Key Functions:**
- `check_admin_access()` – Verify admin privileges
- `get_all_users()` – Fetch user list
- `create_new_user()` – Add user to database
- `update_user_role()` – Change user role
- `update_user_active_status()` – Toggle account
- `reset_user_password()` – Reset password
- `delete_user()` – Remove user account

**Data Source:** `users`, `sessions` tables
**Access Control:** Admin-only
**Security:** Password hashing, session invalidation on changes

---

### 15. Login Page (`pages/login.py`)

**Purpose:** User authentication
**Features:**
- Username and password input fields
- Secure session creation
- Rate limiting (5 failed attempts = lock)
- Password validation
- Redirect to Dashboard on success
- Error messaging

**Workflow:**
1. User enters credentials
2. Validation against `users` table
3. Password verification
4. Session creation in `sessions` table
5. Redirect to Dashboard_Overview.py

**Security Measures:**
- Password hashing verification
- Session tokens
- Timeout enforcement
- Rate limiting
- IP logging

---

### 16. Home Page (`app.py`)

**Purpose:** Introductory landing page
**Features:**
- Platform overview
- Key features highlight
- Technology stack display
- Getting started guide
- Navigation to login
- Responsive design

**Sections:**
- Hero banner with background image
- Feature cards
- Technology stack
- Quick links
- Call-to-action button

---

## 3. Database Schema Details

### Core Tables

| Table               | Purpose                          | Key Relationships                 |
| ------------------- | -------------------------------- | --------------------------------- |
| `users`             | User accounts and auth           | FK: sessions.user_id              |
| `sessions`          | Active user sessions             | FK: users.id                      |
| `splunk_logs`       | SIEM events from Splunk          | Referenced by: threat_scores      |
| `threat_scores`     | Computed threat classifications  | FK: splunk_logs (event_id)        |
| `performance_metrics` | KPI tracking                   | No FK                             |
| `threat_intel_feeds` | IOC reputation data             | Referenced by: threat_scoring     |
| `system_config`     | Configuration parameters        | No FK                             |

### users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100),
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin','analyst','viewer') DEFAULT 'viewer',
    last_login DATETIME,
    created_at DATETIME NOT NULL,
    active BOOLEAN DEFAULT 1
);
```

### splunk_logs Table
```sql
CREATE TABLE splunk_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE NOT NULL,
    timestamp TEXT NOT NULL,
    host TEXT,
    source TEXT,
    sourcetype TEXT,
    event_data TEXT NOT NULL,
    severity TEXT,
    raw_log TEXT,
    indexed_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### threat_scores Table
```sql
CREATE TABLE threat_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT,
    score REAL NOT NULL,
    severity TEXT,
    category TEXT,
    ai_context TEXT,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (event_id) REFERENCES splunk_logs(event_id)
);
```

---

## 4. Data Flows and Integrations

### Data Ingestion
1. **Splunk API** → Fetch logs → Store in `splunk_logs`
2. **Threat Intelligence Feeds** → Parse IOCs → Store in `threat_intel_feeds`
3. **Firewall Logs** → Parse syslog → Store in `splunk_logs`

### Processing Pipeline
1. Logs arrive in `splunk_logs`
2. **Threat Scoring** engine processes:
   - Severity weight from log metadata
   - Frequency count (incidents from same source)
   - Reputation lookup (threat_intel_feeds)
   - AI confidence (Mistral analysis via AI_Log_Analysis.py)
3. Final score → `threat_scores` table
4. High scores trigger auto-block (pfSense API)

### Visualization Flow
- Dashboard_Overview → Aggregates all data for KPIs
- Live_Threat_Monitor → Streams latest logs + geolocation
- Performance_Metrics → Calculates and displays KPIs
- Server_Performance → System metrics via psutil
- Threat_Scoring → Score details and block history

---

## 5. Authentication and Authorization

### Authentication System
- **Type:** Streamlit session-based
- **Storage:** `users` table (SQLite)
- **Password Hashing:** bcrypt (imported, not currently enforced)
- **Session Management:** Streamlit state + `sessions` table

### Session Timeout
- **Duration:** 30 minutes (configured in `config/security.yaml`)
- **Enforcement:** `check_session_timeout()` in session_manager.py
- **On Expiry:** Auto-redirect to login page

### Authorization Levels
- **Admin:** Full access to all pages including User_Management and System_Configuration
- **Analyst:** Access to monitoring and analysis pages
- **Viewer:** Read-only access to dashboards

### Rate Limiting
- **Failed Login Attempts:** 5 attempts = temporary account lock
- **Duration:** Configurable (default: 15 minutes)
- **Logging:** IP address and timestamp recorded

---

## 6. Configuration Files

### `config/security.yaml`
```yaml
secret_key: "replace_with_strong_secret_key"
session_timeout_minutes: 30
password_policy:
  min_length: 10
  require_uppercase: true
  require_digit: true
  require_special: true
max_failed_login_attempts: 5
lockout_duration_minutes: 15
```

### `config/splunk_config.yaml`
```yaml
host: 172.20.10.3
port: 8000
username: admin
password: changeme
ssl_verify: false
earliest_time: -30d@d
latest_time: now
default_query: |
  index=main | stats count by severity
```

### `config/mistral_config.yaml`
```yaml
ollama_host: localhost
ollama_port: 11434
model_name: mistral:latest
use_gpu: true
timeout_seconds: 30
```

### `config/thresholds.json`
```json
{
  "severity_weights": {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 2,
    "info": 1
  },
  "threat_score_thresholds": {
    "low": {"min": 0, "max": 40},
    "medium": {"min": 41, "max": 70},
    "high": {"min": 71, "max": 100}
  },
  "auto_block_threshold": 75
}
```

---

## 7. Testing and Validation

### Unit Tests
| Test File              | Purpose                       | Commands                  |
| ---------------------- | ----------------------------- | ------------------------- |
| test_splunk_connection.py | Verify Splunk API connectivity | `pytest test_splunk_connection.py` |
| test_message_rfc822.py    | Email parsing validation       | `pytest test_message_rfc822.py` |

### Test Scenarios
| Scenario                  | Expected Result                        | Tools Used       |
| ------------------------- | -------------------------------------- | ---------------- |
| Valid login              | Session created, redirect to dashboard | Manual            |
| Invalid credentials      | Error message, no session              | Manual            |
| Expired session          | Redirect to login page                 | Timer simulation  |
| SQL injection attempt    | Query sanitized, no data leakage       | sqlmap (optional) |
| Brute force attack       | Account lockout after 5 attempts       | Manual             |
| Threat score calculation | Score matches formula output           | pytest            |
| Geolocation accuracy     | IPs mapped to correct countries        | ipapi.co test     |
| Mistral integration      | Valid JSON response extraction         | pytest, Ollama    |

---

## 8. Dependencies and Requirements

See `requirements.txt` for all Python packages:
- **streamlit** – Web framework
- **pandas** – Data manipulation
- **plotly** – Interactive charts
- **sqlite3** – Database (built-in)
- **requests** – HTTP client
- **pydeck** – Geolocation mapping
- **psutil** – System metrics
- **pyyaml** – Config file parsing
- **ipaddress** – IP validation
- **re** – Regex operations

---

## 9. Deployment Considerations

### Prerequisites
1. Python 3.8+
2. Splunk instance running at 172.20.10.3:8000
3. Ollama with Mistral model installed
4. pfSense API accessible (optional for blocking)
5. SQLite database initialized

### Startup
```bash
pip install -r requirements.txt
python database/init_db.py  # Initialize database
python database/seed_users.py  # Create admin user
streamlit run app.py
```

### Default Login
- **Username:** admin
- **Password:** admin (should change on first login)

### Production Checklist
- [ ] Update `secret_key` in security.yaml
- [ ] Configure real Splunk credentials
- [ ] Set strong password policy
- [ ] Enable SSL for pfSense integration
- [ ] Configure external threat feeds
- [ ] Set proper session timeout
- [ ] Review and update all API endpoints
- [ ] Enable database backups
- [ ] Configure logging to external service
- [ ] Test failover scenarios

---

## 10. Deliverables Summary

| Component                         | Status | Description                                    |
| --------------------------------- | ------ | ---------------------------------------------- |
| Streamlit Dashboard               | Done   | Multi-page SPA with auth                       |
| SQLite Database                   | Done   | Schema with users, logs, scores, metrics       |
| Mistral LLM Integration           | Done   | Log analysis with confidence scoring           |
| Threat Scoring Engine             | Done   | 4-factor weighted algorithm                    |
| Splunk Integration                | Done   | Real-time log ingestion and filtering          |
| Geolocation Threat Map            | Done   | PyDeck-based visualization (Oman-centered)     |
| Auto-Defense Module               | Done   | pfSense API integration with block tracking    |
| Performance Analytics             | Done   | KPI dashboard with historical trends           |
| Server Performance Monitor        | Done   | Real-time CPU, memory, disk, network metrics   |
| User Management                   | Done   | Admin panel for account control                |
| Forensics & Reports               | Done   | Post-incident analysis and export              |


---

**Last Updated:** December 8, 2025  
**Project Owner:** Alkhalil-Alzakwani  
**Repository:** https://github.com/Alkhalil-Alzakwani/FYP

---
