log_file_path = "sample_logs.txt"

suspicious_rules={
    "failed login": "MEDIUM",
    "failed": "LOW",
    "unauthorized": "HIGH",
    "brute force": "HIGH",
    "port scan": "HIGH",
    "malware": "HIGH",
    "suspicious": "MEDIUM",
    "unknown device": "MEDIUM",
    "data exfiltration": "HIGH",
    "high risk": "HIGH",
    "attack": "HIGH",
    "blocked": "MEDIUM"
}

def analyze_log_line(log_line):
   lower_line = clean_line.lower()
   for keyword,severity in suspicious_rules.items():
      if keyword in lower_line:
         return{
                "log": lower_line,
                "matched_keyword": keyword,
                "severity": severity
         }
   return None
total_logs = 0
suspicious_logs = []
with open(log_file_path, "r") as file:
   for line in file:
        clean_line = line.strip()
        
        if clean_line == "":
          continue
        total_logs += 1

        result = analyze_log_line(clean_line)
        if result is not None:
           suspicious_logs.append(result)
        
suspicious_count = len(suspicious_logs)

high_count = 0
medium_count = 0
low_count = 0

for item in suspicious_logs:
  if item["severity"] == "HIGH":
     high_count += 1
  elif item["severity"] == "MEDIUM":
     medium_count += 1
  elif item["severity"] == "LOW":
     low_count += 1


if high_count > 0:
   risk_level = "HIGH"
elif medium_count > 0:
   risk_level = "MEDIUM"
elif low_count > 0 :
   risk_level = "LOW"
else:
   risk_level = "LOW"


print ("=== AI Log Analyzer ===")
print()
print ("Scanning Log File: ", log_file_path)
print()

print("--- Suspicious Logs Found ---")

if suspicious_count == 0:
   print("No suspicious logs found.") 
else:
  for index, item in enumerate(suspicious_logs, start=1):
    print(f"{index}. [SUSPICIOUS]")
    print(f"  Log: {item['log']}")
    print(f"  Matched Keyword: {item['matched_keyword']}") 
    print(f"  Severity: {item['severity']}")
print()

print("\n --- Security Summary ----")
print("Total logs scanned: ",total_logs)
print("Suspicion events found: ", suspicious_count)
print("High Severity Events:",high_count)
print("Medium Severity Events:",medium_count)
print("Low Severity Events:", low_count)
print("Overall Risk level: ", risk_level)




           
