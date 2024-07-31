import re
import requests
from bs4 import BeautifulSoup

def print_banner():
    banner = """
    ╔════════════════════════════════════════════════════════════╗
    ║                                                            ║
    ║   ████████╗██╗  ██╗███████╗██╗ █████╗                      ║
    ║   ╚══██╔══╝██║  ██║██╔════╝██║██╔══██╗                     ║
    ║      ██║   ███████║█████╗  ██║███████║                     ║
    ║      ██║   ██╔══██║██╔══╝  ██║██╔══██║                     ║
    ║      ██║   ██║  ██║███████╗██║██║  ██║                     ║
    ║      ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═╝                     ║
    ║                                                            ║
    ║   Threat Hunting & Extraction of Indicators Analyzer       ║
    ║                                                            ║
    ╚════════════════════════════════════════════════════════════╝
    """
    print(banner)

def extract_iocs(text):
    patterns = {
        'ip': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b',
        'url': r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',  # Added missing comma here
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'cve': r'CVE-\d{4}-\d{4,7}',
        'bitcoin': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        'mac': r'(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})',
        'cidr': r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b',
        'file_path': r'(?:/[^/\n]+)+|(?:[A-Za-z]:\\[^/\n\\]+(?:\\[^/\n\\]+)*)',
        'registry_key': r'HKEY_[A-Z_]+(?:\\[A-Za-z0-9_]+)+',
        'user_agent': r'User-Agent: .+',
        'asn': r'\bAS\d+\b'
    }

    iocs = {ioc_type: re.findall(pattern, text) for ioc_type, pattern in patterns.items()}
    return iocs

def generate_splunk_rule(iocs, selected_iocs):
    rule = "index=* sourcetype=*\n"
    conditions = []

    field_mappings = {
        'ip': ('src_ip', 'dest_ip'),
        'domain': ('url', 'domain'),
        'md5': ('file_hash',),
        'sha1': ('file_hash',),
        'sha256': ('file_hash',),
        'url': ('url',),
        'email': ('src_user', 'dest_user'),
        'cve': ('vulnerability',),
        'bitcoin': ('bitcoin_address',),
        'mac': ('src_mac', 'dest_mac'),
        'cidr': ('src_ip', 'dest_ip'),
        'file_path': ('file_path',),
        'registry_key': ('registry_key',),
        'user_agent': ('http_user_agent',),
        'asn': ('src_asn', 'dest_asn')
    }

    for ioc_type in selected_iocs:
        if iocs[ioc_type]:
            fields = field_mappings.get(ioc_type, (ioc_type,))
            condition = " OR ".join(f"{field} IN ({','.join(iocs[ioc_type])})" for field in fields)
            conditions.append(f"({condition})")

    rule += " OR ".join(conditions)
    rule += f"\n| stats count by {', '.join(set(field for ioc_type in selected_iocs for field in field_mappings.get(ioc_type, (ioc_type,))))}\n"
    rule += "| where count > 0"

    return rule

def main():
    print_banner()
    print("Welcome to THEIA: Threat Hunting & Extraction of Indicators Analyzer!")

    # Get user input for the article URL or file path
    source = input("Enter the URL or file path of the threat report/news article: ")

    # Read the content
    try:
        if source.startswith('http'):
            response = requests.get(source)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            content = soup.get_text()
        else:
            with open(source, 'r') as file:
                content = file.read()
    except Exception as e:
        print(f"Error reading the source: {e}")
        return

    # Extract IOCs
    iocs = extract_iocs(content)

    # Let user select which IOCs to include
    print("\nAvailable IOC types:")
    for i, ioc_type in enumerate(iocs.keys(), 1):
        print(f"{i}. {ioc_type}")
    
    selected_indices = input("Enter the numbers of IOC types to include (comma-separated, or 'all'): ")
    if selected_indices.lower() == 'all':
        selected_iocs = list(iocs.keys())
    else:
        selected_iocs = [list(iocs.keys())[int(i) - 1] for i in selected_indices.split(',')]

    # Print selected IOCs
    print("\nExtracted IOCs:")
    for ioc_type in selected_iocs:
        if iocs[ioc_type]:
            print(f"{ioc_type.upper()}: {', '.join(iocs[ioc_type])}")

    # Generate Splunk rule
    splunk_rule = generate_splunk_rule(iocs, selected_iocs)

    # Print and optionally save results
    print("\nGenerated Splunk Threat Detection Rule:")
    print(splunk_rule)

    save_option = input("\nDo you want to save the results to a file? (y/n): ")
    if save_option.lower() == 'y':
        filename = input("Enter the filename to save results: ")
        with open(filename, 'w') as f:
            f.write("Extracted IOCs:\n")
            for ioc_type in selected_iocs:
                if iocs[ioc_type]:
                    f.write(f"{ioc_type.upper()}: {', '.join(iocs[ioc_type])}\n")
            f.write("\nGenerated Splunk Threat Detection Rule:\n")
            f.write(splunk_rule)
        print(f"Results saved to {filename}")

    print("Thank you for using THEIA! Happy threat hunting!")


if __name__ == "__main__":
    main()