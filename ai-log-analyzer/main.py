log_file_path = "sample_logs.txt"

suspicious_keywords=[
    "failed login",
    "failed",
    "unauthorized",
    "brute force",
    "port scan",
    "malware",
    "suspicious",
    "unknown device",
    "data exfiltration",
    "high risk"
    "attack"
    "blocked"

]
with open(log_file_path, "r") as file:
    for line in file:
        clean_line = line.strip()
        lower_line = clean_line.lower()

        for keyword in suspicious_keywords:
            if keyword in lower_line:
                print("[SUSPICIOUS]", clean_line)
                break
           
