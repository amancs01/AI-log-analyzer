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

total_logs = 0
suspicious_logs = []

print()
print()
print ("        === AI Log Analyzer ===       ")
print()
print ("Scanning Log File: ", log_file_path)
print()

print("--- Suspicious Logs Found ---")

with open(log_file_path, "r") as file:
    for line in file:
        clean_line = line.strip()

        if clean_line == "":
          continue

        total_logs += 1
        lower_line = clean_line .lower()

        for keyword in suspicious_keywords:
            if keyword in lower_line:
                suspicious_logs.append(clean_line)
                break

suspicious_count = len(suspicious_logs)

if suspicious_count == 0:
   print("No suspicious logs found.") 

print()

print("\n --- Security Summary ----")
print("Total logs scanned: ",total_logs)
print("Suspicion events found: ", suspicious_count)

if suspicious_count == 0:
  risk_level = "low"

elif suspicious_count <= 5:
   risk_level = "medium"

else:
   risk_level = "high"

print ("Risk level: ", risk_level)



           
