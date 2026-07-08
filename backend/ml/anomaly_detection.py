from collections import defaultdict


def detect_brute_force(parsed_logs):

    failed_attempts = defaultdict(int)
    usernames = {}
    alerts = []

    for log in parsed_logs:

        if log["event"] == "Failed":

            ip = log["ip_address"]

            failed_attempts[ip] += 1
            usernames[ip] = log["username"]

    for ip, count in failed_attempts.items():

        if count >= 3:

            alerts.append({

                "attack_type": "Brute Force",

                "severity": "High",

                "attacker_ip": ip,

                "failed_attempts": count,

                "target_user": usernames[ip],

                "recommendation": "Block the IP, reset credentials and enable MFA."

            })

    return alerts