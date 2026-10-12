Day 23: Authentication Log Analysis

Cyber Security Internship — VEDA Technology

Project Overview

This project analyzes synthetic authentication logs to understand successful and failed login patterns and identify potentially suspicious activity.

Objectives

- Analyze authentication events.
- Group login events by username and source IP address.
- Identify repeated failed login attempts.
- Compare successful and failed logins.
- Recommend security improvements.

Tools Used

- Python
- Excel
- CSV authentication log dataset

Analysis Method

1. Load the synthetic authentication log dataset.
2. Check and clean the data.
3. Group events by username and source IP.
4. Count successful and failed login attempts.
5. Flag suspicious patterns for further review.
6. Summarize findings and recommendations.

Security Recommendations

- Monitor repeated failed login attempts.
- Investigate unusual source IP addresses.
- Use multi-factor authentication where available.
- Apply rate limiting or account lockout policies appropriately.
- Keep authentication logs protected and review them regularly.

Project Structure

- "README.md" — Project overview and methodology
- "auth_logs.csv" — Synthetic sample dataset
- "analyze_logs.py" — Python analysis script
- "report/" — Authentication analysis report

Internship Details

- Task: Day 23 — Authentication Log Analysis
- Organization: VEDA Technology
