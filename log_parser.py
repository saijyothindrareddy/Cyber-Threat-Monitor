def parse_logs(filepath):

    logs = []

    with open(filepath, "r") as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            parts = line.split()

            # Example log format:
            # 2026-03-11 10:20:30 LOGIN_FAILED user=admin ip=192.168.1.10

            timestamp = parts[0] + " " + parts[1]
            event = parts[2]

            user = "unknown"
            ip = "0.0.0.0"

            for part in parts:
                if part.startswith("user="):
                    user = part.split("=")[1]
                if part.startswith("ip="):
                    ip = part.split("=")[1]

            logs.append({
                "timestamp": timestamp,
                "event": event,
                "user": user,
                "ip": ip
            })

    return logs