import tempfile
import os


def parse_logs(filepath):

    logs = []

    with open(filepath, "r", encoding="utf-8") as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            parts = line.split()

            # Skip invalid/incomplete lines
            if len(parts) < 3:
                continue

            timestamp = parts[0] + " " + parts[1]
            event = parts[2]

            user = "unknown"
            ip = "0.0.0.0"

            for part in parts:

                if part.startswith("user="):
                    user = part.split("=", 1)[1]

                if part.startswith("ip="):
                    ip = part.split("=", 1)[1]

            logs.append({
                "timestamp": timestamp,
                "event": event,
                "user": user,
                "ip": ip
            })

    return logs


def parse_log_content(content):

    temp_path = None

    try:

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            delete=False,
            encoding="utf-8"
        ) as temp_file:

            temp_file.write(content)
            temp_path = temp_file.name

        return parse_logs(temp_path)

    finally:

        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)