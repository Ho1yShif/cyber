import json
import re
import time
import subprocess
import argparse
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 30
SLEEP = 0.5
THREADS = 5


def lookup(domain: str) -> Dict[str, Any]:
    try:
        result = subprocess.run(
            ["whois", domain], capture_output=True, text=True, timeout=TIMEOUT
        )
        if result.returncode != 0:
            return {"error": "WHOIS command failed", "stderr": result.stderr}
        return {"data": result.stdout}
    except Exception as e:
        return {"error": f"Lookup failed: {str(e)}"}


def load_domains_from_file(filename: str) -> List[str]:
    with open(filename, "r") as file:
        lines = file.readlines()
        # Strip whitespace and filter out comments and blank lines
        domains = []
        for line in lines:
            line = line.strip()  # Remove leading/trailing whitespace including newlines
            # Skip empty lines and comments
            if line and not line.startswith("#"):
                # Handle multiple domains per line (space-separated)
                line_domains = line.split()
                domains.extend(line_domains)
    return domains


def handle_input() -> List[str]:
    parser = argparse.ArgumentParser(description="Lookup WHOIS data for domains")
    parser.add_argument("--file", "-f", help="File containing domains")
    parser.add_argument(
        "domains", nargs="*", help="Space-separated domain names to lookup"
    )
    args = parser.parse_args()
    if not args.file and not args.domains:
        parser.print_help()
        exit(1)
    if args.file:
        return load_domains_from_file(args.file)
    return args.domains


def parse(data: str) -> Dict[str, Any]:
    data = data.split("\n")
    data = [item.split(":") for item in data]
    data = {
        item[0]: item[1].strip()
        for item in data
        if len(item) >= 2
        and not item[0].startswith("%")
        and not item[0].startswith("#")
    }
    return data


def return_registrar(domain: str) -> str:
    time.sleep(SLEEP)
    # Remove www prefix and any protocol prefixes to get the base domain
    normalized_domain = re.sub(r"^(https?://)?www\.", "", domain.lower())
    # Also remove any trailing protocol prefixes if they exist
    normalized_domain = re.sub(r"^https?://", "", normalized_domain)

    whois_result = lookup(normalized_domain)

    # Check if lookup returned an error
    if "error" in whois_result:
        return whois_result["error"]

    # Parse the successful WHOIS data
    data = parse(whois_result["data"])

    # Convert all keys to lowercase for easier matching
    data_lower = {key.lower(): value for key, value in data.items()}

    # Try different possible registrar field names in order of preference
    registrar_fields = [
        "registrar",
        "registrar name",
        "sponsoring registrar",
        "registrar organization",
        "registrant organization",
        "registrant",
    ]

    for field in registrar_fields:
        if field in data_lower and data_lower[field]:
            return data_lower[field]
    return "Not found"


def return_registrars(domains: List[str]) -> Dict[str, str]:
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        registrars = list(executor.map(return_registrar, domains))
        result = {domain: registrar for domain, registrar in zip(domains, registrars)}
    return result


if __name__ == "__main__":
    domains = handle_input()
    result = return_registrars(domains)
    result_json = json.dumps(result)
    print(result_json)
