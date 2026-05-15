log_file_path = "sample_logs.txt"

with open(log_file_path, "r") as file:
    for line in file:
        print(line.strip())
