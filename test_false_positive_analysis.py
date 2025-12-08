"""
Test script to analyze false positive rates by source.
Shows Source, Total Legitimate Events, Flagged as Malicious, False Positive Rate, and Notes.
"""

import sqlite3
import pandas as pd
from pathlib import Path

def main():
    # Database path
    DB_PATH = Path('database/cyber_defense.db')
    
    # Connect to database
    conn = sqlite3.connect(str(DB_PATH))
    
    # Query to analyze false positive performance by source
    # Assumption: info/low = legitimate traffic
    # medium/high/critical = flagged as malicious
    query = '''
    SELECT 
        COALESCE(source, 'Unknown') as source,
        SUM(CASE WHEN severity IN ('info', 'low') OR severity IS NULL THEN 1 ELSE 0 END) as legitimate_events,
        SUM(CASE WHEN severity IN ('medium', 'high', 'critical') THEN 1 ELSE 0 END) as flagged_malicious,
        CASE 
            WHEN COUNT(*) > 0 THEN 
                ROUND(CAST(SUM(CASE WHEN severity IN ('medium', 'high', 'critical') THEN 1 ELSE 0 END) AS FLOAT) / COUNT(*) * 100, 2)
            ELSE 0 
        END as false_positive_rate,
        COUNT(*) as total_events,
        GROUP_CONCAT(DISTINCT severity) as severity_breakdown
    FROM splunk_logs
    GROUP BY source
    ORDER BY false_positive_rate DESC, total_events DESC
    '''
    
    # Execute query
    df = pd.read_sql_query(query, conn)
    
    # Generate notes based on analysis
    def generate_notes(row):
        if row['false_positive_rate'] == 0:
            return 'All events classified as legitimate'
        elif row['false_positive_rate'] < 5:
            return 'Excellent - Very low false positive rate'
        elif row['false_positive_rate'] < 15:
            return 'Good - Acceptable false positive rate'
        elif row['false_positive_rate'] < 30:
            return 'Moderate - May need tuning'
        else:
            return 'High - Requires rule optimization'
    
    df['notes'] = df.apply(generate_notes, axis=1)
    
    # Display results
    print('\n' + '='*120)
    print('FALSE POSITIVE ANALYSIS BY SOURCE - TEST RESULTS')
    print('='*120)
    print()
    
    if df.empty:
        print('No data found in splunk_logs table.')
    else:
        # Format for display
        display_df = df[['source', 'legitimate_events', 'flagged_malicious', 'false_positive_rate', 'notes']].copy()
        display_df.columns = ['Source', 'Total Legitimate Events', 'Flagged as Malicious', 'False Positive Rate (%)', 'Notes']
        
        print(display_df.to_string(index=False))
        print()
        print('='*120)
        
        # Summary statistics
        total_events = df['total_events'].sum()
        total_legitimate = df['legitimate_events'].sum()
        total_flagged = df['flagged_malicious'].sum()
        overall_fp_rate = (total_flagged / total_events * 100) if total_events > 0 else 0
        
        print(f'\nSUMMARY STATISTICS:')
        print(f'  Total Sources Analyzed: {len(df)}')
        print(f'  Total Events: {total_events:,}')
        print(f'  Total Legitimate Events: {total_legitimate:,} ({total_legitimate/total_events*100:.2f}%)')
        print(f'  Total Flagged as Malicious: {total_flagged:,} ({total_flagged/total_events*100:.2f}%)')
        print(f'  Overall False Positive Rate: {overall_fp_rate:.2f}%')
        print('='*120)
        
        # Detailed breakdown by severity
        print('\nSEVERITY DISTRIBUTION BY SOURCE:')
        severity_query = '''
        SELECT 
            source,
            severity,
            COUNT(*) as count,
            ROUND(CAST(COUNT(*) AS FLOAT) / (SELECT COUNT(*) FROM splunk_logs WHERE source = s.source) * 100, 2) as pct_of_source
        FROM splunk_logs s
        WHERE severity IS NOT NULL
        GROUP BY source, severity
        ORDER BY source, count DESC
        '''
        severity_df = pd.read_sql_query(severity_query, conn)
        
        for source in df['source'].unique():
            source_data = severity_df[severity_df['source'] == source]
            if not source_data.empty:
                print(f'\n  {source}:')
                for _, row in source_data.iterrows():
                    print(f'    - {row["severity"]}: {row["count"]} events ({row["pct_of_source"]:.1f}%)')
        
        print('='*120)
    
    conn.close()

if __name__ == '__main__':
    main()
