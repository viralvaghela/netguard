import subprocess
import requests
from colorama import init, Fore, Style

init(autoreset=True)  # Initialize colorama for cross-platform colored output

# Replace 'YOUR_VT_API_KEY' with your actual VirusTotal API key
VT_API_KEY = 'YOUR_VT_API_KEY'
# Replace 'YOUR_VT_API_KEY' with your actual IPInfo API key
INFO_API_KEY = "YOUR_VT_API_KEY"


def print_banner():
    print(Fore.RED + r"""
 ███▄    █ ▓█████▄▄▄█████▓  ▄████  █    ██  ▄▄▄       ██▀███  ▓█████▄ 
 ██ ▀█   █ ▓█   ▀▓  ██▒ ▓▒ ██▒ ▀█▒ ██  ▓██▒▒████▄    ▓██ ▒ ██▒▒██▀ ██▌
▓██  ▀█ ██▒▒███  ▒ ▓██░ ▒░▒██░▄▄▄░▓██  ▒██░▒██  ▀█▄  ▓██ ░▄█ ▒░██   █▌
▓██▒  ▐▌██▒▒▓█  ▄░ ▓██▓ ░ ░▓█  ██▓▓▓█  ░██░░██▄▄▄▄██ ▒██▀▀█▄  ░▓█▄   ▌
▒██░   ▓██░░▒████▒ ▒██▒ ░ ░▒▓███▀▒▒▒█████▓  ▓█   ▓██▒░██▓ ▒██▒░▒████▓ 
░ ▒░   ▒ ▒ ░░ ▒░ ░ ▒ ░░    ░▒   ▒ ░▒▓▒ ▒ ▒  ▒▒   ▓▒█░░ ▒▓ ░▒▓░ ▒▒▓  ▒ 
░ ░░   ░ ▒░ ░ ░  ░   ░      ░   ░ ░░▒░ ░ ░   ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ▒  ▒ 
   ░   ░ ░    ░    ░      ░ ░   ░  ░░░ ░ ░   ░   ▒     ░░   ░  ░ ░  ░ 
         ░    ░  ░              ░    ░           ░  ░   ░        ░    
                                                               ░      
""")
    print(Fore.GREEN + Style.BRIGHT +
          "NetGuard - Checking Outgoing Traffic and Detecting Malicious Activity")
    print("-" * 70 + Style.RESET_ALL)


def get_foreign_addresses():
    netstat_output = subprocess.check_output(['netstat', '-n', '-o', '-a'])
    lines = netstat_output.decode().split('\n')

    foreign_addresses = set()
    for line in lines:
        if "TCP" in line or "UDP" in line:
            parts = line.split()
            if len(parts) >= 3:
                try:
                    address, port = parts[2].split(
                        ':')  # Split address and port
                    foreign_addresses.add((address, port))
                except ValueError:
                    pass  # Skip addresses without a colon

    print(f"Found {len(foreign_addresses)} foreign addresses.")
    return foreign_addresses


def get_ip_details(ip_address, port):
    if ip_address == '*' or ip_address == '[::]:0':
        return None  # Skip wildcard and IPv6 addresses

    api_url = f"http://ipinfo.io/{ip_address}?token={INFO_API_KEY}"

    response = requests.get(api_url)
    print(f"Response status code: {response.status_code}")
    if response.status_code == 200:
        details = response.json()
        details['port'] = port
        return details
    else:
        return response.text


def print_colored_details(address, ip_details, malicious):
    print(
        f"Details for {Fore.CYAN}{address[0]}:{address[1]}{Style.RESET_ALL}:")
    print(f"   IP: {Fore.GREEN}{ip_details.get('ip', 'N/A')}{Style.RESET_ALL}")
    print(
        f"   Location: {Fore.YELLOW}{ip_details.get('city', 'N/A')}, {ip_details.get('region', 'N/A')}, {ip_details.get('country', 'N/A')}{Style.RESET_ALL}")
    print(
        f"   ISP: {Fore.MAGENTA}{ip_details.get('org', 'N/A')}{Style.RESET_ALL}")
    print(f"   Port: {Fore.CYAN}{address[1]}{Style.RESET_ALL}")

    if malicious is not None:
        if malicious:
            print(Fore.RED + "   Malicious: Yes" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "   Malicious: No" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW +
              "   Malicious: Unknown (Error querying VirusTotal)" + Style.RESET_ALL)
    print()


def is_malicious(ip_address):
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(vt_url, headers=headers)
        response.raise_for_status()
        report = response.json()
        malicious = report['data']['attributes']['last_analysis_stats']['malicious'] > 0
        return malicious
    except Exception as e:
        print(f"Error querying VirusTotal: {e}")
        return None


def main():
    print_banner()
    foreign_addresses = get_foreign_addresses()

    for address in foreign_addresses:
        ip_details = get_ip_details(address[0], address[1])
        malicious = is_malicious(address[0])
        if ip_details:
            print_colored_details(address, ip_details, malicious)


if __name__ == "__main__":
    main()
