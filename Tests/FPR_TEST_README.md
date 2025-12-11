# False Positive Rate (FPR) Testing

## Overview

The False Positive Rate (FPR) test measures the frequency of legitimate events that are incorrectly classified as malicious by the AI-based detection system. This is a critical metric for evaluating the accuracy and reliability of threat detection rules.

## What is False Positive Rate?

**False Positive Rate (FPR)** = False Positives / (False Positives + True Negatives)

Where:
- **False Positives (FP)**: Legitimate/benign events incorrectly flagged as malicious
- **True Negatives (TN)**: Legitimate/benign events correctly identified as benign

## Why FPR Matters

High FPR indicates that the system is generating too many false alarms, which can:
- Overwhelm security analysts with alerts
- Reduce trust in the detection system
- Waste time investigating non-threats
- Lead to "alert fatigue" where real threats get missed

## Interpretation Guide

| FPR Range | Status | Interpretation |
|-----------|--------|----------------|
| < 5% | EXCELLENT | Very low false positive rate. System is highly accurate. |
| 5-10% | GOOD | Acceptable false positive rate. Minor tuning recommended. |
| 10-20% | MODERATE | Elevated false positive rate. Review detection rules. |
| > 20% | HIGH | High false positive rate. Significant tuning needed. |

## Usage

### Basic Usage (Local Data)
```bash
python Tests/check_false_positive_rate.py
```

### With Splunk Integration
```bash
python Tests/check_false_positive_rate.py --use-splunk
```

### Custom Data Sources
```bash
python Tests/check_false_positive_rate.py --logs path/to/logs.csv --detections path/to/detections.csv
```

## Command Line Options

- `--logs <path>`: Path to logs CSV file (default: `data/sample_logs.csv`)
- `--detections <path>`: Path to AI detections CSV file (default: `data/detected_from_db.csv`)
- `--use-splunk`: Fetch additional data from Splunk
- `--time-range <range>`: Time range for Splunk query (default: `-7d@d` for last 7 days)

## Output

The test generates:

### 1. Console Output
- Overall FPR metrics
- FPR breakdown by sourcetype
- Sample false positive examples
- Interpretation and recommendations

### 2. CSV Reports
- `data/false_positive_rate_results.csv`: Historical FPR results
- `data/fpr_by_sourcetype.csv`: FPR breakdown by sourcetype

## Example Output

```
================================================================================
 FALSE POSITIVE RATE (FPR) ANALYSIS
================================================================================

OVERALL METRICS:
--------------------------------------------------------------------------------
Total Events Analyzed:        150
Benign Events (Legitimate):   100
True Negatives (Correct):     90
False Positives (Errors):     10
--------------------------------------------------------------------------------
False Positive Rate (FPR):    10.00%
Detection Accuracy:           90.00%

INTERPRETATION:
Status: ⚠ MODERATE
       Elevated false positive rate. Review detection rules.

FALSE POSITIVE RATE BY SOURCETYPE:
--------------------------------------------------------------------------------
        Sourcetype  Total Events  Benign Events  False Positives  True Negatives FPR (%)
    pfsense:syslog            54             25                4              21    16.0
            syslog            38             38                4              34   10.53
wineventlog:system            37             37                2              35    5.41
```

## Event Classification Logic

### Benign (Legitimate) Events
Events are classified as benign based on:
- **Action**: allow, permit, pass, accept
- **Severity**: info, low, notice
- **Category**: normal, admin, system, maintenance
- **Absence** of malicious keywords

### Malicious Indicators (Exclusions)
Events with these keywords are NOT classified as benign:
- attack, malware, threat, intrusion, exploit
- vulnerability, suspicious, blocked, denied
- alert, critical, phishing, virus, trojan

### AI Detection Matching
Events are considered flagged if:
1. Present in AI detections file (matched by event_id)
2. `threat_detected`, `is_threat`, or `flagged` is True
3. `ai_verdict` is "malicious", "threat", or "suspicious"
4. `threat_score` > 70

## Generating Test Data

To generate synthetic test data for demonstration:
```bash
python Tests/generate_fpr_test_data.py
```

This creates:
- 100 benign events (normal traffic)
- 50 malicious events (actual threats)
- AI detections with ~15% expected FPR

## Integration with Splunk

The test can fetch real-time data from your Splunk instance:

1. Ensure Splunk configuration is set in `config/splunk_config.yaml`
2. Use the `--use-splunk` flag
3. Optionally specify time range with `--time-range`

Example:
```bash
python Tests/check_false_positive_rate.py --use-splunk --time-range "-24h@h"
```

## Reducing False Positives

If FPR is high, consider:

1. **Tune Detection Rules**:
   - Review AI model thresholds
   - Adjust threat scoring weights
   - Refine pattern matching rules

2. **Whitelist Known Good Sources**:
   - Internal IP ranges
   - Trusted domains
   - Administrative accounts

3. **Context-Aware Detection**:
   - Consider time of day
   - User behavior baselines
   - Historical patterns

4. **Feedback Loop**:
   - Review false positives regularly
   - Update training data
   - Retrain AI models

## System Architecture Note

As mentioned, this system provides detection and alerting capabilities. The actual prevention is handled by:
- **Firewall**: pfSense for network-level blocking
- **IDS/IPS**: Snort for intrusion detection
- **Endpoint Protection**: Antivirus/EDR solutions

The FPR test helps ensure that recommendations to these systems are accurate and minimize operational overhead.

## Related Tests

- `check_detection_rate.py`: Measures ability to detect actual threats (True Positive Rate)
- `check_sourcetypes.py`: Validates data sources and sourcetypes

## Troubleshooting

### No Events Available
- Check that data files exist and contain data
- Run `generate_fpr_test_data.py` to create sample data
- Use `--use-splunk` to fetch from Splunk

### High FPR
- Review detection thresholds
- Check for overly aggressive rules
- Examine sample false positives in output

### Splunk Connection Issues
- Verify Splunk configuration in `config/splunk_config.yaml`
- Check network connectivity to Splunk host
- Ensure credentials are correct

## Support

For questions or issues:
1. Review the interpretation guide above
2. Check sample false positives for patterns
3. Examine detection rules and thresholds
4. Consider tuning AI model parameters
