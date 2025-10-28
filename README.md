Multilayered Cyber Defense Platform Dashboard Documentation

1. Overall Architecture

  Purpose

The Streamlit Dashboard serves as the central command and visualization interface for the multilayered cyber defense system. It integrates the following components:

* Firewall logs (pfSense)
* IDS/IPS alerts (Snort)
* SIEM analytics (Splunk)
* Threat intelligence feeds
* LLM (Mistral:latest) for contextual phishing analysis
* SQL database for persistence, scoring, and performance tracking

---

2. Project Directory Structure

```
FYP-Project/
│
├── app.py                                # Main Streamlit entry point
│
├── pages/
│   ├── 1_Dashboard_Overview.py           # Main metrics and summary
│   ├── 2_Live_Threat_Monitor.py          # Real-time Splunk log stream
│   ├── 3_AI_Log_Analysis.py              # Mistral LLM analysis page
│   ├── 4_Threat_Scoring.py               # Threat scoring algorithms
│   ├── 5_Performance_Metrics.py          # KPI tracking and reports
│   ├── 6_System_Configuration.py         # API keys, DB setup, thresholds
│   └── 7_Forensics_And_Reports.py        # Incident reports and exports
│
├── config/
│   ├── db_config.yaml                    # Database connection info
│   ├── splunk_config.yaml                # Splunk connection & query params
│   ├── mistral_config.yaml               # LLM model config
│   └── thresholds.json                   # Detection & severity limits
│
├── database/
│   ├── schema.sql                        # SQL schema definition
│   ├── init_db.py                        # Script to initialize tables
│   └── queries.py                        # Reusable SQL queries
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

5. Streamlit Pages and Their Functionality

1. Dashboard Overview (`pages/1_Dashboard_Overview.py`)

**Purpose:** Executive summary view
**Features:**

* Total attacks detected (real-time counter)
* Detection Rate, Prevention Rate, False Positive Rate
* Recent top 10 phishing events
* Threat map (by source country using GeoIP)
* Charts: Attack types, severity distribution
  **Data source:** performance_metrics, threat_scores, Splunk logs

---

2. Live Threat Monitor (`pages/2_Live_Threat_Monitor.py`)

**Purpose:** Stream real-time logs from Splunk API
**Features:**

* Live updating data table (auto-refresh every 10 seconds)
* Filters by source, severity, type
* Color-coded severity badges
* Option to block IP via pfSense API
  **Linked to:** Splunk REST API (localhost:8000), pfSense API

---

3. AI Log Analysis (`pages/3_AI_Log_Analysis.py`)

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

4. Threat Scoring (`pages/4_Threat_Scoring.py`)

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

5. Performance Metrics (`pages/5_Performance_Metrics.py`)

**Purpose:** Track detection and prevention KPIs
**KPIs Calculated:**

* Detection Rate = Detected / Total attempts
* Prevention Rate = Blocked / Total attempts
* False Positive Rate = FP / (TP + FP)
* MTTD (Mean Time to Detect)
* MTTR (Mean Time to Respond)
* Auto-Containment = Auto-blocked / Total incidents

**Graphs:**

* Line chart: Detection Rate over time
* Bar chart: Auto-containment rate
* Scatter plot: Severity vs. response time

**Data Source:** performance_metrics, system logs

---

6. System Configuration (`pages/6_System_Configuration.py`)

**Purpose:** Administrative configuration panel
**Features:**

* Set thresholds for severity and LLM confidence
* Manage API keys for Splunk and pfSense
* Configure database connection credentials
* Enable or disable Auto-block feature

---

7. Forensics and Reports (`pages/7_Forensics_And_Reports.py`)

**Purpose:** Post-incident forensic analysis and reporting
**Features:**

* Generate downloadable incident reports (PDF or CSV)
* Display raw PCAP and Splunk event data
* Visualize timeline of incident events
* Export performance summaries

**Linked to:** threat_scores, siem_logs

---

6. LLM Integration (Mistral:latest)

**API Logic (models/mistral_analyzer.py):**

* Input: Splunk log line or JSON event
* Preprocess: Remove noise and extract entities (IP, URL, domain)
* Prompt Template:

  ```
  Analyze the following log for phishing behavior. 
  Return JSON: { "confidence": float, "summary": string, "action": string }
  Log: {{log_content}}
  ```
* Output: Stored in `threat_scores`
* Used for predictive scoring and descriptive analysis

---

7. Mathematical and Testing Components

  Formulas

| Metric              | Formula                             | Purpose                  |
| ------------------- | ----------------------------------- | ------------------------ |
| Detection Rate      | DR = (Detected / Total) × 100       | Efficiency of IDS/SIEM   |
| False Positive Rate | FPR = (FP / (FP + TP)) × 100        | Accuracy measurement     |
| Prevention Rate     | PR = (Blocked / Detected) × 100     | Firewall responsiveness  |
| MTTR                | MTTR = Σ(Response_Time) / Incidents | Response efficiency      |
| Threat Score        | Weighted sum (see section 4)        | Classification threshold |

---

  Testing and Validation

| Tool                          | Test Purpose                | Expected Output              |
| ----------------------------- | --------------------------- | ---------------------------- |
| GoPhish                       | Simulated phishing emails   | Verify detection rate        |
| Social-Engineer Toolkit (SET) | URL and attachment phishing | Evaluate prevention accuracy |
| Splunk synthetic logs         | Stress test SIEM parsing    | Validate throughput          |
| Unit tests (pytest)           | Validate module functions   | Ensure correctness           |
| LLM simulation test           | Analyze random logs         | Validate AI accuracy         |

---

8. Deliverables Summary

| Component                         | Description                                   |
| --------------------------------- | --------------------------------------------- |
| Streamlit Dashboard               | Centralized analytics and control interface   |
| SQL Database                      | Unified storage for logs, scores, and metrics |
| Mistral LLM Integration           | Contextual phishing analysis                  |
| Threat Scoring Engine             | Multi-factor threat evaluation                |
| Splunk Integration                | Real-time log ingestion                       |
| Auto-Defense Module (pfSense API) | Tiered blocking and rollback                  |
| Performance Analytics             | KPI visualization and reporting               |

---
