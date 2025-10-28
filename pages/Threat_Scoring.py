"""
Threat Scoring (pages/Threat_Scoring.py)

Purpose: Implement the threat scoring engine Algorithm Components:

    Severity Weight (Sw): Based on alert type
    Frequency Weight (Fw): Number of repeated incidents from same IP
    Reputation Weight (Rw): From threat feeds
    AI Confidence (Aic): From Mistral output
    Final Formula:

Final_Score = (Sw × 0.4) + (Fw × 0.2) + (Rw × 0.1) + (Aic × 0.3)

Output Categories:

    Low (0–40)
    Medium (41–70)
    High (71–100)

Automatic blocking is triggered for High category.

"""