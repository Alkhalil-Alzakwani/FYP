"""
Test script to analyze phishing detection performance without editing existing code.
Shows Campaign ID, Total Attempts, Correctly Detected, Missed, and Detection Rate.
"""

import sqlite3
import pandas as pd
from pathlib import Path

def main():
    # Database path
    DB_PATH = Path('database/cyber_defense.db')
    
    # Connect to database
    conn = sqlite3.connect(str(DB_PATH))
    
    # Query to analyze detection performance
    # Assumption: critical/high severity = correctly detected phishing
    # info/low/medium severity = missed or false negatives
    query = '''
    SELECT 
        COALESCE(source, 'Unknown Campaign') as campaign_id,
        COUNT(*) as total_attempts,
        SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) as correctly_detected,
        SUM(CASE WHEN severity IN ('info', 'low', 'medium') OR severity IS NULL THEN 1 ELSE 0 END) as missed,
        ROUND(CAST(SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS FLOAT) / COUNT(*) * 100, 2) as detection_rate
    FROM splunk_logs
    GROUP BY source
    ORDER BY total_attempts DESC
    '''
    
    # Execute query
    df = pd.read_sql_query(query, conn)
    
    # Display results
    print('\n' + '='*100)
    print('PHISHING DETECTION ANALYSIS - TEST RESULTS')
    print('='*100)
    print()
    
    if df.empty:
        print('No data found in splunk_logs table.')
    else:
        # Format column names for display
        df.columns = ['Campaign ID', 'Total Attempts', 'Correctly Detected', 'Missed', 'Detection Rate (%)']
        print(df.to_string(index=False))
        print()
        print('='*100)
        print(f'Total Campaigns/Sources: {len(df)}')
        print(f'Total Attempts Across All Campaigns: {df["Total Attempts"].sum()}')
        total_detected = df['Correctly Detected'].sum()
        total_attempts = df['Total Attempts'].sum()
        overall_rate = (total_detected / total_attempts * 100) if total_attempts > 0 else 0
        print(f'Overall Detection Rate: {overall_rate:.2f}%')
        print('='*100)
        
        # Summary by severity
        print('\nDETECTION BREAKDOWN BY SEVERITY:')
        severity_query = '''
        SELECT 
            COALESCE(severity, 'Unknown') as severity,
            COUNT(*) as count,
            ROUND(CAST(COUNT(*) AS FLOAT) / (SELECT COUNT(*) FROM splunk_logs) * 100, 2) as percentage
        FROM splunk_logs
        GROUP BY severity
        ORDER BY count DESC
        '''
        severity_df = pd.read_sql_query(severity_query, conn)
        severity_df.columns = ['Severity', 'Count', 'Percentage (%)']
        print(severity_df.to_string(index=False))
        print('='*100)
    
    conn.close()

if __name__ == '__main__':
    main()
