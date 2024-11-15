import os
import socket
from androguard.misc import AnalyzeAPK  # Ensure this import is present

# Hardcoded vulnerability rules
vulnerability_rules = [
    {'issue': "Weak Cryptography Usage", 'method_name': "javax/crypto/Cipher", 'description': "Use of weak cryptographic algorithms (e.g., DES, MD5). Consider using stronger algorithms like AES."},
    {'issue': "Hardcoded API Keys", 'method_name': "Landroid/content/SharedPreferences", 'description': "Sensitive API keys or tokens might be hardcoded in the app, which is a security risk."},
    {'issue': "Insecure HTTP Usage", 'method_name': "Ljava/net/HttpURLConnection", 'description': "Use of HTTP connections detected. Consider using HTTPS to secure communication."},
    {'issue': "Unprotected WebView", 'method_name': "Landroid/webkit/WebView", 'description': "Potentially unprotected WebView usage detected. Ensure proper security configurations."},
    {'issue': "Dynamic Code Loading", 'method_name': "Ldalvik/system/DexClassLoader", 'description': "Dynamic code loading detected, which may introduce security vulnerabilities if not properly managed."},
    {'issue': "Logging Sensitive Information", 'method_name': "Landroid/util/Log", 'description': "Potential logging of sensitive information detected. Avoid logging sensitive data in production apps."},
    {'issue': "Insecure File Permissions", 'method_name': "Landroid/os/FileUtils", 'description': "Insecure file permissions might be granted. Ensure files are properly secured and have appropriate permissions."}
]

# Function to identify open ports
def identify_open_ports(host='localhost'):
    open_ports = []
    for port in range(20, 1025):  # Scans ports from 20 to 1024
        print(f"Scanning port {port}...")  # Print which port is being scanned
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)  # Reduce timeout to 0.5 seconds
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

# Function to scan APK for vulnerabilities
def scan_apk(apk_path):
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")
    
    print("Analyzing APK file...")  # Start message
    a, d, dx = AnalyzeAPK(apk_path)
    vulnerabilities_found = []

    for rule in vulnerability_rules:
        method_name_rule = rule.get('method_name')
        for method in dx.get_methods():
            if method_name_rule in method.name:
                vulnerabilities_found.append({
                    'issue': rule.get('issue', 'Unknown issue'),
                    'method': method.name,
                    'description': rule.get('description', 'No description available')
                })
    
    print(f"Vulnerability scan complete. Found {len(vulnerabilities_found)} issues.")  # End message
    return vulnerabilities_found

# Function to save the report
def save_report(vulnerabilities, open_ports, file_path):
    with open(file_path, 'w') as report_file:
        report_file.write("Security Scan Report\n")
        report_file.write("====================\n\n")
        report_file.write(f"Open Ports: {open_ports}\n\n")

        if vulnerabilities:
            report_file.write(f"Found {len(vulnerabilities)} vulnerabilities:\n\n")
            for vuln in vulnerabilities:
                report_file.write(f"Issue: {vuln['issue']}\n")
                report_file.write(f"Method: {vuln['method']}\n")
                report_file.write(f"Description: {vuln['description']}\n\n")
        else:
            report_file.write("No vulnerabilities found.\n")
