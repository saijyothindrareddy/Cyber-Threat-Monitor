def detect_threats(logs):

    failed_attempts = {}
    alerts = []

    for log in logs:

        ip = log["ip"]
        user = log["user"]

        # Brute Force Detection

        if log["event"] == "LOGIN_FAILED":

            if ip not in failed_attempts:
                failed_attempts[ip] = 0

            failed_attempts[ip] += 1

            attempts = failed_attempts[ip]

            if attempts >= 3:

                if attempts >= 8:
                    severity = "Critical"
                    risk_score = 95

                elif attempts >= 5:
                    severity = "High"
                    risk_score = 80

                else:
                    severity = "Medium"
                    risk_score = 60

                alerts.append({
                    "timestamp": log["timestamp"],
                    "ip": ip,
                    "user": user,
                    "type": "Brute Force Attack",
                    "attempts": attempts,
                    "severity": severity,
                    "risk_score": risk_score,
                    "status": "Open"
                })

        # Simulated Enterprise Threats

        last_digit = int(ip.split(".")[-1])

        if last_digit % 11 == 0:

            alerts.append({
                "timestamp": log["timestamp"],
                "ip": ip,
                "user": user,
                "type": "SQL Injection",
                "attempts": 1,
                "severity": "High",
                "risk_score": 85,
                "status": "Open"
            })

        elif last_digit % 13 == 0:

            alerts.append({
                "timestamp": log["timestamp"],
                "ip": ip,
                "user": user,
                "type": "XSS Attack",
                "attempts": 1,
                "severity": "High",
                "risk_score": 82,
                "status": "Open"
            })

        elif last_digit % 17 == 0:

            alerts.append({
                "timestamp": log["timestamp"],
                "ip": ip,
                "user": user,
                "type": "Port Scanning",
                "attempts": 1,
                "severity": "Medium",
                "risk_score": 65,
                "status": "Open"
            })

        elif last_digit % 19 == 0:

            alerts.append({
                "timestamp": log["timestamp"],
                "ip": ip,
                "user": user,
                "type": "Credential Stuffing",
                "attempts": 1,
                "severity": "High",
                "risk_score": 88,
                "status": "Open"
            })

        elif last_digit % 23 == 0:

            alerts.append({
                "timestamp": log["timestamp"],
                "ip": ip,
                "user": user,
                "type": "Malware Detection",
                "attempts": 1,
                "severity": "Critical",
                "risk_score": 96,
                "status": "Open"
            })

        elif last_digit % 29 == 0:

            alerts.append({
                "timestamp": log["timestamp"],
                "ip": ip,
                "user": user,
                "type": "Ransomware Activity",
                "attempts": 1,
                "severity": "Critical",
                "risk_score": 99,
                "status": "Open"
            })

    return alerts