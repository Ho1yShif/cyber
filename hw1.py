import time
import subprocess
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 30
SLEEP = 0.5
THREADS = 5


def lookup(domain: str) -> str:
    try:
        result = subprocess.run(
            ["whois", domain], capture_output=True, text=True, timeout=TIMEOUT
        )
    except subprocess.TimeoutExpired:
        return "Timeout"
    return result.stdout


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


def load_domains(filename: str) -> List[str]:
    with open(filename, "r") as file:
        domains = file.read().strip()
    return domains.split(" ")


def return_registrar(domain: str) -> str:
    time.sleep(SLEEP)
    data = lookup(domain)
    data = parse(data)
    if "Registrar" not in data:
        return "Not found"
    registrar = data["Registrar"]
    return registrar


def return_registrars(domains: List[str]) -> List[str]:
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        result = list(executor.map(return_registrar, domains))
    return result


if __name__ == "__main__":
    domains = load_domains("input.txt")
    result = return_registrars(domains)
    print(result)
