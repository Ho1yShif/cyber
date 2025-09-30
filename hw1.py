import time
import subprocess
import argparse
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 30
SLEEP = 0.5
THREADS = 5


def lookup(domain: str) -> tuple[str, Optional[str]]:
    """
    Lookup WHOIS data for a domain.
    Returns (whois_data, error_message) where error_message is None on success.
    """
    try:
        result = subprocess.run(
            ["whois", domain], capture_output=True, text=True, timeout=TIMEOUT
        )
        if result.returncode != 0:
            return "", f"WHOIS command failed: {result.stderr.strip()}"
        return result.stdout, None
    except subprocess.TimeoutExpired:
        return "", "Timeout"
    except Exception as e:
        return "", f"Error: {str(e)}"


def extract_registrable_domain(domain: str) -> str:
    """
    Extract registrable domain from subdomain.
    Simple implementation - for production use tldextract library.
    """
    # Remove common subdomains
    parts = domain.lower().split(".")
    if len(parts) > 2 and parts[0] in ["www", "mail", "ftp", "blog", "shop"]:
        return ".".join(parts[1:])
    return domain


def parse_whois_data(data: str) -> Dict[str, str]:
    """Parse WHOIS data into key-value pairs."""
    result = {}
    lines = data.split("\n")

    for line in lines:
        line = line.strip()
        if not line or line.startswith("%") or line.startswith("#"):
            continue

        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            if value:  # Only store non-empty values
                result[key] = value

    return result


def find_registrar(parsed_data: Dict[str, str]) -> Optional[str]:
    """
    Find registrar from parsed WHOIS data.
    Handles various registrar field names and prioritizes them.
    """
    # Registrar field variants in order of preference
    registrar_fields = [
        "registrar",
        "sponsoring registrar",
        "registrar name",
        "registrar organization",
        "registrant organization",
    ]

    for field in registrar_fields:
        if field in parsed_data:
            registrar = parsed_data[field]
            # Skip URLs and WHOIS servers
            if not any(
                x in registrar.lower() for x in ["http", "whois", ".com/", ".net/"]
            ):
                return registrar

    return None


def check_referral(parsed_data: Dict[str, str]) -> Optional[str]:
    """Check if WHOIS data contains a referral to another WHOIS server."""
    referral_fields = ["whois server", "referral whois server", "whois"]

    for field in referral_fields:
        if field in parsed_data:
            referral = parsed_data[field]
            if referral and not referral.lower().startswith("http"):
                return referral
    return None


def load_domains_from_file(filename: str) -> List[str]:
    """
    Load domains from file, handling newlines, spaces, blanks, and comments.
    """
    domains = []
    try:
        with open(filename, "r") as file:
            lines = file.readlines()

        for line in lines:
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # Split line by whitespace and add all non-empty parts
            parts = line.split()
            for part in parts:
                part = part.strip()
                if part and not part.startswith("#"):
                    domains.append(part)

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return []
    except Exception as e:
        print(f"Error reading file '{filename}': {e}")
        return []

    return domains


def get_registrar_for_domain(domain: str) -> tuple[str, str]:
    """
    Get registrar for a domain with comprehensive error handling.
    Returns (domain, result) where result is either registrar name or error message.
    """
    time.sleep(SLEEP)

    # Normalize domain (handle subdomains)
    normalized_domain = extract_registrable_domain(domain)

    # First WHOIS lookup
    whois_data, error = lookup(normalized_domain)
    if error:
        return domain, error

    if not whois_data.strip():
        return domain, "No WHOIS data returned"

    # Parse the WHOIS data
    parsed_data = parse_whois_data(whois_data)

    # Try to find registrar
    registrar = find_registrar(parsed_data)
    if registrar:
        return domain, registrar

    # Check for referral and try again
    referral_server = check_referral(parsed_data)
    if referral_server:
        try:
            # Follow referral
            result = subprocess.run(
                ["whois", "-h", referral_server, normalized_domain],
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
            )
            if result.returncode == 0 and result.stdout.strip():
                referral_parsed = parse_whois_data(result.stdout)
                referral_registrar = find_registrar(referral_parsed)
                if referral_registrar:
                    return domain, referral_registrar
        except Exception:
            pass  # Fall through to "No registrar found"

    return domain, "No registrar found"


def get_registrars_for_domains(domains: List[str]) -> List[tuple[str, str]]:
    """Get registrars for multiple domains using thread pool."""
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        results = list(executor.map(get_registrar_for_domain, domains))
    return results


def print_results(results: List[tuple[str, str]], output_format: str = "mapping"):
    """Print results in the specified format."""
    if output_format == "json":
        import json

        result_dict = {domain: registrar for domain, registrar in results}
        print(json.dumps(result_dict, indent=2))
    else:  # mapping format (default)
        for domain, registrar in results:
            print(f"{domain} -> Registrar: {registrar}")


def main():
    parser = argparse.ArgumentParser(
        description="WHOIS registrar lookup tool",
        epilog="Examples:\n"
        "  python hw1.py example.com google.com\n"
        "  python hw1.py --file input.txt\n"
        "  python hw1.py --file domains.txt --format json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "domains", nargs="*", help="Space-separated domain names to lookup"
    )

    parser.add_argument(
        "--file",
        "-f",
        dest="filename",
        help="File containing domains (whitespace/newline separated, # for comments)",
    )

    parser.add_argument(
        "--format",
        choices=["mapping", "json"],
        default="mapping",
        help="Output format (default: mapping)",
    )

    args = parser.parse_args()

    # Collect domains from CLI args and/or file
    domains = []

    if args.domains:
        domains.extend(args.domains)

    if args.filename:
        file_domains = load_domains_from_file(args.filename)
        domains.extend(file_domains)

    # Fallback to input.txt if no domains specified (backward compatibility)
    if not domains:
        print("No domains specified. Trying to load from input.txt...")
        domains = load_domains_from_file("input.txt")

    if not domains:
        parser.print_help()
        print(
            "\nError: No domains to process. Specify domains as arguments or use --file option."
        )
        return 1

    print(f"Processing {len(domains)} domain(s)...")
    results = get_registrars_for_domains(domains)
    print_results(results, args.format)
    return 0


if __name__ == "__main__":
    exit(main())
