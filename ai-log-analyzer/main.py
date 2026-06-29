from rules import suspicious_rules

log_file_path = "sample_logs.txt"


def analyze_log_line(log_line):
   lower_line = log_line.lower()
   for keyword,severity in suspicious_rules.items():
      if keyword in lower_line:
         return{
                "log": lower_line,
                "matched_keyword": keyword,
                "severity": severity
         }
   return None

def count_severity_levels(suspicious_logs):
   
   severity_count = {
   "HIGH": 0,
   "MEDIUM" : 0,
   "LOW" : 0
   }
   
   for item in suspicious_logs:
     severity = item["severity"]

     if severity in severity_count:
      severity_count[severity] += 1
   return severity_count
    

def calculate_risk_level(severity_count):
   if severity_count["HIGH"] > 0:
      return "HIGH"

   elif severity_count["MEDIUM"] > 0:
      return "MEDIUM"  

   elif severity_count["LOW"] > 0 :
      return "LOW"
   
   else:
      return "LOW"

def print_report(total_logs, suspicious_logs, severity_count, risk_level):
   
   suspicious_count = len(suspicious_logs)

   print ("=== AI Log Analyzer ===")
   print()
   print ("Scanning Log File: ", log_file_path)
   print()


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
   print("High Severity Events:",severity_count["HIGH"])
   print("Medium Severity Events:",severity_count["MEDIUM"])
   print("Low Severity Events:", severity_count["LOW"])
   print("Overall Risk level: ", risk_level)


def main():
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
         
   severity_count = count_severity_levels(suspicious_logs)
   risk_level = calculate_risk_level(severity_count)

   print_report(total_logs, suspicious_logs, severity_count, risk_level)

if __name__=="__main__":
   main()



           
