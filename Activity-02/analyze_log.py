from collections import Counter

def analyze_failed_logins(logfile_path, min_count):
    counter = Counter()

    with open(logfile_path, 'r') as log_file:
        for line in log_file:
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                ip = match.group("src_ip")
                counter[ip] += 1

    # Filter out IPs below min_count
    filtered = Counter({ip: count for ip, count in counter.items() if count >= min_count})

    _print_counter(filtered)

from collections import defaultdict

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

    # Sort by number of IPs
    sorted_creds = sorted(cred_map.items(), key=lambda x: len(x[1]), reverse=True)

    print(f"{'Username':<15} {'Password':<15} {'IP Count':<10}")
    print("-" * 45)
    for (username, password), ip_set in sorted_creds:
        print(f"{username:<15} {password:<15} {len(ip_set):<10}")
