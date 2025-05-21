import re
import argparse
from collections import Counter, defaultdict

# Provided regex patterns (assume these are in the starter code)
FAILED_LOGIN_PATTERN = re.compile(
    r"login attempt \[user (?P<username>.+), password (?P<password>.+)\] from (?P<src_ip>\d+\.\d+\.\d+\.\d+)")
SUCCESS_LOGIN_PATTERN = re.compile(
    r"login succeeded \[user (?P<username>.+), password (?P<password>.+)\] from (?P<src_ip>\d+\.\d+\.\d+\.\d+)")
COMMAND_PATTERN = re.compile(r'CMD: (?P<cmd>.+)')

def _print_counter(counter):
    print(f"{'Item':<20} {'Count':<5}")
    print("-" * 26)
    for item, count in counter.most_common():
        print(f"{item:<20} {count:<5}")

def analyze_failed_logins(logfile_path, min_count):
    counter = Counter()
    with open(logfile_path, 'r') as log_file:
        for line in log_file:
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                ip = match.group("src_ip")
                counter[ip] += 1

    filtered = Counter({ip: count for ip, count in counter.items() if count >= min_count})
    _print_counter(filtered)

def analyze_successful_creds(logfile_path):
    cred_map = defaultdict(set)
    with open(logfile_path, 'r') as log_file:
        for line in log_file:
            match = SUCCESS_LOGIN_PATTERN.search(line)
            if match:
                username = match.group("username")
                password = match.group("password")
                ip = match.group("src_ip")
                cred_map[(username, password)].add(ip)

    sorted_creds = sorted(cred_map.items(), key=lambda x: len(x[1]), reverse=True)

    print(f"{'Username':<15} {'Password':<15} {'IP Count':<10}")
    print("-" * 45)
    for (username, password), ip_set in sorted_creds:
        print(f"{username:<15} {password:<15} {len(ip_set):<10}")

def analyze_top_commands(logfile_path):
    cmd_counter = Counter()
    with open(logfile_path, "r") as f:
        for line in f:
            match = COMMAND_PATTERN.search(line)
            if match:
                cmd = match.group("cmd").strip()
                cmd_counter[cmd] += 1

    print("\nTop 10 Shell Commands:")
    print(f"{'Command':<40} {'Count'}")
    print("-" * 50)
    for cmd, count in cmd_counter.most_common(10):
        print(f"{cmd:<40} {count}")

# Main entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze Cowrie log files.")
    parser.add_argument("logfile", help="Path to Cowrie log file.")
    parser.add_argument("--task", required=True,
        choices=["failed-logins", "successful-creds", "top-commands"])
    parser.add_argument("--min-count", type=int, default=3,
        help="Minimum count to display for failed-logins task.")
    
    args = parser.parse_args()

    if args.task == "failed-logins":
        analyze_failed_logins(args.logfile, args.min_count)
    elif args.task == "successful-creds":
        analyze_successful_creds(args.logfile)
    elif args.task == "top-commands":
        analyze_top_commands(args.logfile)
