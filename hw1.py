import time
import subprocess
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor


def lookup(domain: str) -> str:
    result = subprocess.run(
        ["whois", domain], capture_output=True, text=True, timeout=30
    )
    return result.stdout


def parse_whois_data(data: str) -> Dict[str, Any]:
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


def split_domains(filename: str) -> List[str]:
    domains = open(filename, "r").read().strip()
    return domains.split(" ")


def return_registrar(domain: str) -> str:
    time.sleep(0.5)
    data = lookup(domain)
    data = parse_whois_data(data)
    registrar = data["Registrar"]
    return registrar


def return_registrars(domains: List[str]) -> List[str]:
    with ThreadPoolExecutor(max_workers=5) as executor:
        result = list(executor.map(return_registrar, domains))
    return result


if __name__ == "__main__":
    domains = split_domains("input.txt")
    result = return_registrars(domains)
    print(result)
