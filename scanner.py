import subprocess

print("~~~ Network Security Analysis Tool ~~~")
print("Discovering devices...\n")

result = subprocess.run(["nmap", "-sn", "192.168.1.0/24"], capture_output=True, text=True)
output = result.stdout.split("\n")

devices = []

for line in output:
    if "Nmap scan report for" in line:
        parts = line.split("for ")[1]
        if "(" in parts:
            name = parts.split("(")[0].strip()
            ip = parts.split("(")[-1].replace(")", "").strip()
        else:
            name = "Unknown"
            ip = parts.strip()
        devices.append((name, ip))

print("Devices found:")
for name, ip in devices:
    print(f"{name} → {ip}")


def scan_target(target):
    result = subprocess.run(
        ["nmap", "-sS", "-sV", "-Pn", "-T4", target],
        capture_output=True,
        text=True
    )
    return result.stdout


def extract_ports(nmap_output):
    ports = []
    lines = nmap_output.split("\n")

    for line in lines:
        if "/tcp" in line and "open" in line:
            parts = line.split()
            port = parts[0]
            service = parts[2] if len(parts) > 2 else "unknown"
            version = " ".join(parts[3:]) if len(parts) > 3 else ""
            ports.append({
                "port": port,
                "service": service,
                "version": version
            })

    return ports


def detect_os(output, hostname, ports):
    output = output.lower()
    hostname = hostname.lower()

    if "windows" in output:
        return "Windows"
    if "android" in output:
        return "Android"
    if "linux" in output:
        if any(p["port"].startswith(("5555", "8080")) for p in ports):
            return "Android"
        else:
            return "Linux"
    if "embedded" in output:
        return "Embedded device"
    if "phone" in hostname or "android" in hostname:
        return "Android"

    return "Unknown"


def check_risk(ports):
    risks = []
    port_numbers = [p["port"].split('/')[0] for p in ports]

    if "21" in port_numbers:
        risks.append("Medium – FTP open (insecure file transfer)")
    if "23" in port_numbers:
        risks.append("High – Telnet open (unencrypted login)")
    if "139" in port_numbers:
        risks.append("Medium – NetBIOS exposed")
    if "445" in port_numbers:
        risks.append("High – SMB exposed (common attack target)")
    if "22" in port_numbers:
        risks.append("Low – SSH open")
    if "80" in port_numbers:
        risks.append("Low – HTTP service running")
    if "443" in port_numbers:
        risks.append("Low – HTTPS service running")
    if "3389" in port_numbers:
        risks.append("High – Remote Desktop exposed")
    if "25" in port_numbers:
        risks.append("Medium – SMTP mail server exposed")

    if not risks:
        risks.append("Low – No common risky ports")

    return risks


print("\nStarting scan\n")

count = 1
for name, target in devices:
    print(f"\nDevice {count}: {name} ({target})\n")

    output = scan_target(target)
    ports = extract_ports(output)
    os_info = detect_os(output, name, ports)

    print(f"OS: {os_info}")
    print("\nOpen ports:")

    if ports:
        for p in ports:
            print(f"- {p['port']} ({p['service']}) {p['version']}")
    else:
        print("None")

    risks = check_risk(ports)

    print("\nRisk Analysis:")
    for r in risks:
        print(f"- {r}")

    print("\n" + "-" * 60)
    count += 1
