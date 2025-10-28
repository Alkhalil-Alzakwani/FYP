"""
Performance Metrics (pages/Performance_Metrics.py)

Purpose: Track detection and prevention KPIs KPIs Calculated:

    Detection Rate = Detected / Total attempts
    Prevention Rate = Blocked / Total attempts
    False Positive Rate = FP / (TP + FP)
    MTTD (Mean Time to Detect)
    MTTR (Mean Time to Respond)
    Auto-Containment = Auto-blocked / Total incidents

Graphs:
    Line chart: Detection Rate over time
    Bar chart: Auto-containment rate
    Scatter plot: Severity vs. response time

Data Source: performance_metrics, system logs

"""