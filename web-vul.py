import requests
from bs4 import BeautifulSoup
import urllib3
import ssl

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to check for security headers
def check_headers(url):
    print("\n[+] Checking Security Headers...")
    response = requests.get(url, verify=False)
    headers = response.headers

    # List of security headers to check for
    security_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection"
    ]
    
    for header in security_headers:
        if header in headers:
            print(f"[+] {header}: Present")
        else:
            print(f"[-] {header}: Not Present")

# Function to check for SSL/TLS certificate details
def check_ssl(url):
    print("\n[+] Checking SSL/TLS...")
    try:
        # Extract hostname from URL
        hostname = url.split("//")[1].split("/")[0]
        ssl_info = ssl.get_server_certificate((hostname, 443))
        print("[+] SSL Certificate Found")
    except Exception as e:
        print(f"[-] SSL Certificate Error: {e}")

# Function to look for HTML forms (could be vulnerable to SQL/XSS)
def check_forms(url):
    print("\n[+] Checking for Forms (potential injection points)...")
    response = requests.get(url, verify=False)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    forms = soup.find_all('form')
    if forms:
        print(f"[+] {len(forms)} Form(s) Found:")
        for form in forms:
            print(f"    Action: {form.get('action')}, Method: {form.get('method')}")
    else:
        print("[-] No Forms Found")

# Function to check for sensitive file exposure (e.g. robots.txt)
def check_sensitive_files(url):
    print("\n[+] Checking for sensitive files...")
    sensitive_files = ["/robots.txt", "/.git/", "/.env", "/admin"]
    
    for file in sensitive_files:
        full_url = url + file
        response = requests.get(full_url, verify=False)
        if response.status_code == 200:
            print(f"[+] Sensitive File Found: {full_url}")
        else:
            print(f"[-] {file}: Not Found")

# Main function
def scan_website(url):
    print(f"\nStarting Vulnerability Scan for {url}")
    
    # Check for security headers
    check_headers(url)
    
    # Check for SSL/TLS vulnerabilities
    check_ssl(url)
    
    # Check for injection points (HTML forms)
    check_forms(url)
    
    # Check for sensitive file exposure
    check_sensitive_files(url)
    
    print("\nScan Complete.")

# Input from user
if __name__ == "__main__":
    target_url = input("Enter the target website URL (e.g., https://example.com): ").strip()
    scan_website(target_url)
