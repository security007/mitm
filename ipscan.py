import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor

def is_live(ip):
    """Check if an IP is live using ping."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        print(f"[*] Checking {ip}",end="\r")
        subprocess.run(["ping", param, "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return ip
    except subprocess.CalledProcessError:
        return None

def scan_ip_range(start_ip, end_ip):
    """Scan a range of IPs and return the live ones."""
    start_parts = list(map(int, start_ip.split('.')))
    end_parts = list(map(int, end_ip.split('.')))
    
    live_ips = []
    with ThreadPoolExecutor() as executor:
        futures = []

        for i in range(start_parts[3], end_parts[3] + 1):
            ip = f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{i}"
            futures.append(executor.submit(is_live, ip))

        for future in futures:
            result = future.result()
            if result:
                live_ips.append(result)

    return live_ips

if __name__ == "__main__":
    start_ip = "192.168.1.1"
    end_ip = "192.168.1.254"

    print("Scanning for live IPs...\n")
    live_ips = scan_ip_range(start_ip, end_ip)

    if live_ips:
        print("\nLive IPs found:")
        for ip in live_ips:
            print(ip)
    else:
        print("No live IPs found.")
