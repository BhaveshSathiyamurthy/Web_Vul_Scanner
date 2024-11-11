import requests
from bs4 import BeautifulSoup
import urllib3
import ssl
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.colors import black
import os
import socket
import time


# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_unique_filename(base_name, extension):
    """Generate a unique filename by adding a suffix if the file already exists."""
    filename = f"{base_name}.{extension}"
    counter = 1
    while os.path.isfile(filename):
        filename = f"{base_name}_{counter}.{extension}"
        counter += 1
    return filename

def add_to_pdf(pdf, text, y, font="Helvetica", size=12, offset=20, max_width=500):
    """Helper function to add text to PDF with wrapping and updates Y position. Adds new page if needed."""
    pdf.setFont(font, size)
    pdf.setFillColor(black)

    # Split text to fit max width
    lines = pdf.beginText(50, y)
    lines.setFont(font, size)
    lines.setFillColor(black)
    words = text.split(' ')
    line = ""

    for word in words:
        if lines.getX() + pdf.stringWidth(line + word, font, size) < max_width:
            line += word + ' '
        else:
            lines.textLine(line.strip())
            line = word + ' '
            y -= offset
            if y < 40:  # Add new page if the Y position is too low
                pdf.drawText(lines)
                pdf.showPage()
                lines = pdf.beginText(50, 800)
                lines.setFont(font, size)
                lines.setFillColor(black)
                y = 800

    # Add remaining text and finalize
    if line:
        lines.textLine(line.strip())
        y -= offset
    pdf.drawText(lines)

    return y


# Function to test for SQL Injection
def check_sql_injection(url, pdf, y):
    y = add_to_pdf(pdf, "\n[+] Testing for SQL Injection...", y, size=14)
    print("\n[+] Testing for SQL Injection...")
    payloads = ["' OR '1'='1", "' OR 1=1--", "' OR 'a'='a"]
    
    response = requests.get(url, verify=False)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    
    found_vulnerabilities = False
    if forms:
        for form in forms:
            for payload in payloads:
                form_data = {}
                for input_tag in form.find_all('input'):
                    input_name = input_tag.get('name')
                    form_data[input_name] = payload
                
                form_action = form.get('action')
                form_method = form.get('method').lower()
                form_url = url if not form_action else url + form_action
                if form_method == 'post':
                    res = requests.post(form_url, data=form_data, verify=False)
                else:
                    res = requests.get(form_url, params=form_data, verify=False)
                
                if "error" in res.text.lower() or "sql" in res.text.lower():
                    result = f"[+] Potential SQL Injection vulnerability found at {form_url}"
                    y = add_to_pdf(pdf, result, y)
                    found_vulnerabilities = True

    if found_vulnerabilities:
        mitigation = "Mitigation for SQL Injection: Use prepared statements and parameterized queries. Validate and sanitize user inputs. Restrict database permissions and use ORM frameworks where possible."
        y = add_to_pdf(pdf, mitigation, y)
    else:
        y = add_to_pdf(pdf, "[-] No SQL Injection vulnerabilities found.", y)
    return y

# Function to check for XSS vulnerabilities
def check_xss(url, pdf, y):
    y = add_to_pdf(pdf, "\n[+] Checking for XSS Vulnerabilities...", y, size=14)
    print("\n[+] Checking for XSS Vulnerabilities...")

    response = requests.get(url, verify=False)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    xss_payloads = ["<script>alert('XSS')</script>", "'><img src=x onerror=alert('XSS')>"]

    if forms:
        result = f"[+] {len(forms)} Form(s) Found for XSS Testing:"
        print(result)
        y = add_to_pdf(pdf, result, y)

        for form in forms:
            form_action = form.get('action')
            form_method = form.get('method').lower() if form.get('method') else 'get'
            
            # Default to url if form_action is None
            form_url = url if not form_action else url + form_action

            for payload in xss_payloads:
                form_data = {}
                for input_tag in form.find_all("input"):
                    input_name = input_tag.get("name")
                    if input_tag.get("type") == "text":
                        form_data[input_name] = payload
                    else:
                        form_data[input_name] = "test"

                if form_method == "post":
                    response = requests.post(form_url, data=form_data, verify=False)
                else:
                    response = requests.get(form_url, params=form_data, verify=False)

                if payload in response.text:
                    vuln_message = f"[+] Potential XSS vulnerability found in form at {form_url}"
                    print(vuln_message)
                    y = add_to_pdf(pdf, vuln_message, y)

                    mitigation = (
                        "Mitigation: Implement input sanitization and encoding. Use Content Security Policy (CSP) headers "
                        "to prevent the execution of unauthorized scripts. Ensure that any user input is properly escaped "
                        "in the web page."
                    )
                    y = add_to_pdf(pdf, mitigation, y)
                    break
            else:
                safe_message = f"[-] No XSS vulnerability detected in form at {form_url}"
                print(safe_message)
                y = add_to_pdf(pdf, safe_message, y)
    else:
        no_form_message = "[-] No forms found for XSS testing."
        print(no_form_message)
        y = add_to_pdf(pdf, no_form_message, y)

    return y

# Function to check for Directory Traversal
def check_directory_traversal(url, pdf, y):
    y = add_to_pdf(pdf, "\n[+] Testing for Directory Traversal...", y, size=14)
    print("\n[+] Testing for Directory Traversal...")
    traversal_payloads = ["../", "..%2F", "%2E%2E%2F"]

    found_vulnerabilities = False
    for payload in traversal_payloads:
        full_url = f"{url}/{payload}etc/passwd"
        response = requests.get(full_url, verify=False)
        if "root:x" in response.text:
            result = f"[+] Directory Traversal vulnerability found at {full_url}"
            y = add_to_pdf(pdf, result, y)
            found_vulnerabilities = True

    if found_vulnerabilities:
        mitigation = "Mitigation for Directory Traversal: Use secure file APIs and restrict access to files outside of designated directories. Validate and sanitize user input, especially on file paths."
        y = add_to_pdf(pdf, mitigation, y)
    else:
        y = add_to_pdf(pdf, "[-] No Directory Traversal vulnerabilities found.", y)
    return y

# Function to check for Open Ports
def check_open_ports(url, pdf, y):
    y = add_to_pdf(pdf, "\n[+] Checking for Open Ports...", y, size=14)
    print("\n[+] Checking for Open Ports...")
    open_ports = []
    hostname = url.split("//")[1].split("/")[0]

    for port in [21, 22, 23, 80, 443, 8080]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((hostname, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    if open_ports:
        result = f"[+] Open Ports Found: {', '.join(map(str, open_ports))}"
        y = add_to_pdf(pdf, result, y)
        mitigation = "Mitigation for Open Ports: Disable unnecessary ports and services. Use firewalls to restrict access to specific ports."
        y = add_to_pdf(pdf, mitigation, y)
    else:
        y = add_to_pdf(pdf, "[-] No open ports found.", y)
    return y

# Function to check for Authentication Weaknesses
def check_auth_weakness(url, pdf, y):
    y = add_to_pdf(pdf, "\n[+] Checking for Authentication Weaknesses...", y, size=14)
    print("\n[+] Checking for Authentication Weaknesses...")
    response = requests.get(url, auth=('admin', 'admin'), verify=False)
    
    if response.status_code == 200:
        result = f"[+] Weak Authentication Found - default credentials 'admin:admin'"
        y = add_to_pdf(pdf, result, y)
        mitigation = "Mitigation for Authentication Weaknesses: Enforce strong password policies and limit access to default credentials. Implement multi-factor authentication (MFA) where possible."
        y = add_to_pdf(pdf, mitigation, y)
    else:
        y = add_to_pdf(pdf, "[-] No weak authentication detected.", y)
    return y

# Function to check for Brute Force Protection
def check_brute_force_protection(url, pdf, y):
    y = add_to_pdf(pdf, "\n[+] Checking for Brute-Force Protection...", y, size=14)
    print("\n[+] Checking for Brute-Force Protection...")
    
    login_attempts = 5
    credentials = {'username': 'testuser', 'password': 'wrongpassword'}
    brute_force_detected = False
    
    for attempt in range(login_attempts):
        response = requests.post(url, data=credentials, verify=False)
        if attempt > 0:
            time.sleep(1)  # Simulate short delay between login attempts

        # Check if the site is applying rate-limiting or account lockout mechanisms
        if "too many attempts" in response.text.lower() or "locked" in response.text.lower():
            result = "[+] Brute-force protection detected: Rate-limiting or account lockout mechanism in place."
            y = add_to_pdf(pdf, result, y)
            brute_force_detected = True
            break
    
    if not brute_force_detected:
        result = "[-] No brute-force protection detected. The site is vulnerable to brute-force attacks."
        y = add_to_pdf(pdf, result, y)
        mitigation = (
            "Mitigation for Brute-Force Vulnerability: "
            "Implement rate-limiting on login attempts, account lockout mechanisms, and CAPTCHA verification. "
            "Also consider IP blocking after multiple failed attempts and enabling multi-factor authentication (MFA) for critical accounts."
        )
        y = add_to_pdf(pdf, mitigation, y)
    else:
        y = add_to_pdf(pdf, "[+] Brute-force protection mechanisms detected.", y)

    return y


# Function to check for Server Misconfigurations
def check_server_misconfigurations(url, pdf, y):
    y = add_to_pdf(pdf, "\n[+] Checking for Server Misconfigurations...", y, size=14)
    print("\n[+] Checking for Server Misconfigurations...")
    headers_to_check = ["Server", "X-Powered-By"]
    response = requests.get(url, verify=False)
    
    found_vulnerabilities = False
    for header in headers_to_check:
        if header in response.headers:
            result = f"[+] {header} Header Found - May reveal server info"
            y = add_to_pdf(pdf, result, y)
            found_vulnerabilities = True

    if found_vulnerabilities:
        mitigation = "Mitigation for Server Misconfigurations: Remove or restrict server information from HTTP headers. Limit access to sensitive configuration files and disable unnecessary services."
        y = add_to_pdf(pdf, mitigation, y)
    else:
        y = add_to_pdf(pdf, "[-] No server misconfigurations detected.", y)
    return y

# Function to check for security headers
def check_headers(url, pdf, y):
    y = add_to_pdf(pdf, "[+] Checking Security Headers...", y, size=14)
    print("\n[+] Checking Security Headers...")
    response = requests.get(url, verify=False)
    headers = response.headers

    security_headers = {
        "Content-Security-Policy": "Mitigation: Set a Content-Security-Policy header to prevent XSS.",
        "Strict-Transport-Security": "Mitigation: Enable Strict-Transport-Security to enforce HTTPS.",
        "X-Content-Type-Options": "Mitigation: Use X-Content-Type-Options to prevent MIME sniffing.",
        "X-Frame-Options": "Mitigation: Use X-Frame-Options to prevent clickjacking.",
        "X-XSS-Protection": "Mitigation: Enable X-XSS-Protection to block XSS attacks."
    }
    
    for header, mitigation in security_headers.items():
        if header in headers:
            result = f"[+] {header}: Present"
            print(result)
            y = add_to_pdf(pdf, result, y)
        else:
            result = f"[-] {header}: Not Present - {mitigation}"
            print(result)
            y = add_to_pdf(pdf, result, y)
    return y

# Function to check for SSL/TLS certificate details
def check_ssl(url, pdf, y):
    y = add_to_pdf(pdf, "\n[+] Checking SSL/TLS...", y, size=14)
    print("\n[+] Checking SSL/TLS...")
    try:
        hostname = url.split("//")[1].split("/")[0]
        ssl_info = ssl.get_server_certificate((hostname, 443))
        result = "[+] SSL Certificate Found"
        print(result)
        y = add_to_pdf(pdf, result, y)
    except Exception as e:
        result = f"[-] SSL Certificate Error: {e} - Mitigation: Ensure a valid SSL certificate is present."
        print(result)
        y = add_to_pdf(pdf, result, y)
    return y

# Function to check for HTML forms (could be vulnerable to SQL/XSS)
def check_forms(url, pdf, y):
    y = add_to_pdf(pdf, "\n[+] Checking for Forms (potential injection points)...", y, size=14)
    print("\n[+] Checking for Forms (potential injection points)...")
    response = requests.get(url, verify=False)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    forms = soup.find_all('form')
    if forms:
        result = f"[+] {len(forms)} Form(s) Found:"
        print(result)
        y = add_to_pdf(pdf, result, y)
        for form in forms:
            action = form.get('action')
            method = form.get('method')
            form_info = f"    Action: {action}, Method: {method} - Mitigation: Sanitize inputs and use parameterized queries."
            print(form_info)
            y = add_to_pdf(pdf, form_info, y)
    else:
        result = "[-] No Forms Found"
        print(result)
        y = add_to_pdf(pdf, result, y)
    return y

# Function to check for sensitive file exposure (e.g., robots.txt)
def check_sensitive_files(url, pdf, y):
    y = add_to_pdf(pdf, "\n[+] Checking for sensitive files...", y, size=14)
    print("\n[+] Checking for sensitive files...")
    sensitive_files = {
        "/robots.txt": "Mitigation: Restrict access to sensitive data in robots.txt.",
        "/.git/": "Mitigation: Prevent access to .git directory to avoid data leaks.",
        "/.env": "Mitigation: Restrict access to .env file containing secrets.",
        "/admin": "Mitigation: Use authentication and IP restrictions on admin panel."
    }
    
    for file, mitigation in sensitive_files.items():
        full_url = url + file
        response = requests.get(full_url, verify=False)
        if response.status_code == 200:
            result = f"[+] Sensitive File Found: {full_url} - {mitigation}"
            print(result)
            y = add_to_pdf(pdf, result, y)
        else:
            result = f"[-] {file}: Not Found"
            print(result)
            y = add_to_pdf(pdf, result, y)
    return y


# Main function
def scan_website(url):
    pdf_filename = get_unique_filename("Vulnerability_Scan_Report", "pdf")
    pdf = canvas.Canvas(pdf_filename, pagesize=A4)
    y = 800  # Initial Y position for adding content to PDF

    title = f"Website Vulnerability Scan Report for {url}"
    print(title)
    y = add_to_pdf(pdf, title, y, size=16, offset=30)

    y = check_sql_injection(url, pdf, y)
    y = check_xss(url, pdf, y)
    y = check_directory_traversal(url, pdf, y)
    y = check_open_ports(url, pdf, y)
    y = check_auth_weakness(url, pdf, y)
    y = check_brute_force_protection(url, pdf, y)
    y = check_server_misconfigurations(url, pdf, y)
    y = check_headers(url, pdf, y)
    y = check_ssl(url, pdf, y)
    y = check_forms(url, pdf, y)
    y = check_sensitive_files(url, pdf, y)

    completion_message = "\nScan Complete."
    print(completion_message)
    y = add_to_pdf(pdf, completion_message, y, size=14, offset=30)

    # Save the PDF
    pdf.save()
    print(f"\n[+] Report saved as {pdf_filename}")

# Input from user
if __name__ == "__main__":
    target_url = input("Enter the target website URL (e.g., https://example.com): ").strip()
    scan_website(target_url)
