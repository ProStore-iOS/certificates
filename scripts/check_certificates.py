import re
import requests
import os
import json
from bs4 import BeautifulSoup, NavigableString, Tag
from pathlib import Path
from datetime import datetime
import sys

BASE_URL = "https://check-p12.applep12.com/"

def get_token(session):
    """Get the CSRF token from the check page."""
    r = session.get(BASE_URL, timeout=20)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    token_input = soup.find("input", {"name": "__RequestVerificationToken"})
    if not token_input:
        raise RuntimeError("Couldn't find __RequestVerificationToken on page")
    return token_input.get("value")

def submit_check(session, token, p12_path, p12_password, mp_path):
    """Submit files for checking."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Referer": BASE_URL,
        "Origin": "https://check-p12.applep12.com",
    }

    files = [
        ("P12File", (p12_path.name, open(p12_path, "rb"), "application/x-pkcs12")),
        ("P12PassWord", (None, p12_password)),
        ("MobileProvisionFile", (mp_path.name, open(mp_path, "rb"), "application/octet-stream")),
        ("__RequestVerificationToken", (None, token)),
    ]

    r = session.post(BASE_URL, files=files, headers=headers, timeout=60)
    r.raise_for_status()
    return r.text

def split_kv(line):
    """Split on either ASCII colon ':' or full-width '：' and return (key, value)."""
    parts = re.split(r'[:：]\s*', line, maxsplit=1)
    if len(parts) == 2:
        return parts[0].strip(), parts[1].strip()
    return parts[0].strip(), ""

def clean_value(raw):
    """Clean and normalize values."""
    if raw is None:
        return ""
    # Remove extra whitespace
    v = re.sub(r'\s+', ' ', raw).strip()
    return v

def lines_from_alert_div(alert_div):
    """Extract text lines from the alert div."""
    lines = []
    cur = []
    for node in alert_div.children:
        if isinstance(node, NavigableString):
            txt = str(node).strip()
            if txt:
                cur.append(txt)
        elif isinstance(node, Tag):
            if node.name == "br":
                if cur:
                    joined = " ".join(cur).strip()
                    if joined:
                        lines.append(joined)
                cur = []
            else:
                txt = node.get_text(" ", strip=True)
                if txt:
                    cur.append(txt)
    if cur:
        joined = " ".join(cur).strip()
        if joined:
            lines.append(joined)
    return [re.sub(r'\s+', ' ', ln).strip() for ln in lines if ln.strip()]

def parse_html(html):
    """Parse the HTML response from the certificate checker."""
    soup = BeautifulSoup(html, "html.parser")
    
    alert_div = soup.find(lambda tag: tag.name == "div" and tag.get("class") and any("alert" in c for c in tag.get("class")))
    if not alert_div:
        return {"error": "No certificate info found in response"}
    
    lines = lines_from_alert_div(alert_div)
    
    data = {
        "certificate": {},
        "mobileprovision": {},
        "binding_certificate_1": {},
    }
    
    def find_index(prefixes, start=0):
        for i in range(start, len(lines)):
            for p in prefixes:
                if lines[i].startswith(p):
                    return i
        return None
    
    cert_idx = find_index(["CertName:", "CertName："])
    mp_idx = find_index(["MP Name:", "MP Name："])
    binding_idx = find_index(["Binding Certificates:", "Binding Certificates："], start=(mp_idx or 0))
    
    # Parse mobileprovision block (dates come from here)
    if mp_idx is not None:
        end = binding_idx if binding_idx is not None else len(lines)
        for ln in lines[mp_idx:end]:
            k, v = split_kv(ln)
            v = clean_value(v)
            lk = k.lower()
            if lk.startswith("mp name"):
                data["mobileprovision"]["name"] = v
            elif lk.startswith("effective date"):
                data["mobileprovision"]["effective"] = v
            elif lk.startswith("expiration date"):
                data["mobileprovision"]["expiration"] = v
    
    # Parse certificate status
    if binding_idx is not None:
        cert1_idx = find_index(["Certificate 1:", "Certificate 1：", "Certificate 1"], start=binding_idx)
        if cert1_idx is not None:
            end = find_index(["Certificate 2:", "Certificate 2：", "Certificate 2"], start=cert1_idx+1) or len(lines)
            for ln in lines[cert1_idx+1:end]:
                k, v = split_kv(ln)
                v = clean_value(v)
                lk = k.lower()
                if lk.startswith("certificate status"):
                    data["binding_certificate_1"]["status"] = v
    
    return data

def convert_date_format(date_str):
    """Convert date from '08/02/23 06:07' to '08/02/23 06:07' (same format, just ensure consistency)."""
    try:
        # Parse the date
        dt = datetime.strptime(date_str, "%m/%d/%y %H:%M")
        # Return in the same format
        return dt.strftime("%m/%d/%y %H:%M")
    except:
        try:
            dt = datetime.strptime(date_str, "%d/%m/%y %H:%M")
            return dt.strftime("%m/%d/%y %H:%M")
        except:
            return date_str

def get_certificate_status(cert_name):
    """Check the status of a single certificate."""
    cert_dir = Path(cert_name)
    
    # Find the .p12 and .mobileprovision files
    p12_files = list(cert_dir.glob("*.p12"))
    mp_files = list(cert_dir.glob("*.mobileprovision"))
    
    if not p12_files or not mp_files:
        print(f"❌ Missing files for {cert_name}")
        return None
    
    p12_path = p12_files[0]
    mp_path = mp_files[0]
    
    # Read password
    password_file = cert_dir / "password.txt"
    if password_file.exists():
        with open(password_file, 'r') as f:
            password = f.read().strip()
    else:
        password = "nezushub.vip"  # Default password
    
    try:
        with requests.Session() as session:
            token = get_token(session)
            html = submit_check(session, token, p12_path, password, mp_path)
            data = parse_html(html)
            
            status = data.get("binding_certificate_1", {}).get("status", "Unknown")
            effective = data.get("mobileprovision", {}).get("effective", "Unknown")
            expiration = data.get("mobileprovision", {}).get("expiration", "Unknown")
            
            # Convert dates to proper format
            if effective != "Unknown":
                effective = convert_date_format(effective)
            if expiration != "Unknown":
                expiration = convert_date_format(expiration)
            
            return {
                "status": "Valid" if status == "Valid" else "Revoked",
                "effective": effective,
                "expiration": expiration,
                "company": cert_name
            }
            
    except Exception as e:
        print(f"❌ Error checking {cert_name}: {str(e)}")
        return None

def parse_readme_table(readme_content):
    """Parse the markdown table from README.md."""
    lines = readme_content.split('\n')
    table_start = -1
    
    # Find the table
    for i, line in enumerate(lines):
        if line.startswith('| Company | Type | Status |'):
            table_start = i
            break
    
    if table_start == -1:
        return []
    
    certificates = []
    # Skip header and separator rows
    for i in range(table_start + 2, len(lines)):
        line = lines[i].strip()
        if not line.startswith('|') or line.startswith('|---'):
            break
        
        # Parse row
        cells = [cell.strip() for cell in line.split('|')[1:-1]]  # Remove empty first/last
        
        if len(cells) >= 5:
            cert_info = {
                "company": cells[0],
                "type": cells[1],
                "status": cells[2],
                "valid_from": cells[3],
                "valid_to": cells[4],
                "download": cells[5] if len(cells) > 5 else "",
                "line_index": i
            }
            certificates.append(cert_info)
    
    return certificates, lines

def update_readme_table(certificates, lines):
    """Update the README.md lines with new certificate statuses."""
    updated_lines = lines.copy()
    
    for cert in certificates:
        idx = cert['line_index']
        row_parts = updated_lines[idx].split('|')
        
        # Update status
        if '✅' in cert['status']:
            new_status = '✅ Signed'
        elif '❌' in cert['status'] or cert['status'] == 'Revoked':
            new_status = '❌ Revoked'
        else:
            new_status = cert['status']
        
        # Update dates
        valid_from = cert['valid_from'] if cert['valid_from'] != 'Unknown' else row_parts[4].strip()
        valid_to = cert['valid_to'] if cert['valid_to'] != 'Unknown' else row_parts[5].strip()
        
        # Reconstruct row
        row_parts[3] = f" {new_status} "
        row_parts[4] = f" {valid_from} "
        row_parts[5] = f" {valid_to} "
        
        updated_lines[idx] = '|'.join(row_parts)
    
    return updated_lines

def update_recommended_cert(lines, certificates):
    """Update the recommended certificate section."""
    for i, line in enumerate(lines):
        if 'Recommend Certificate' in line and i + 1 < len(lines):
            # Find which certificate is recommended
            next_line = lines[i + 1].strip()
            if 'China Telecommunications Corporation V2' in next_line:
                # Find this certificate in our list
                for cert in certificates:
                    if 'China Telecommunications Corporation V2' in cert['company']:
                        status = '✅ Signed' if cert['status'] == 'Valid' else '❌ Revoked'
                        lines[i + 1] = f"**China Telecommunications Corporation V2 - {status}**"
                        break
    
    return lines

def main():
    # Read README.md
    with open('README.md', 'r', encoding='utf-8') as f:
        readme_content = f.read()
    
    # Parse table
    certificates, lines = parse_readme_table(readme_content)
    
    if not certificates:
        print("No certificates found in README.md")
        return
    
    print(f"Found {len(certificates)} certificates in README.md")
    
    # Check each certificate
    updated_certs = []
    for cert_info in certificates:
        company = cert_info['company']
        print(f"Checking {company}...")
        
        result = get_certificate_status(company)
        if result:
            # Update cert info with new status
            cert_info['status'] = result['status']
            cert_info['valid_from'] = result['effective']
            cert_info['valid_to'] = result['expiration']
            updated_certs.append(cert_info)
            
            status_emoji = '✅' if result['status'] == 'Valid' else '❌'
            print(f"  {status_emoji} Status: {result['status']}")
            print(f"  📅 Valid From: {result['effective']}")
            print(f"  📅 Valid To: {result['expiration']}")
        else:
            print(f"  ⚠️  Could not check status")
    
    # Update the README content
    updated_lines = update_readme_table(updated_certs, lines)
    updated_lines = update_recommended_cert(updated_lines, updated_certs)
    
    # Write back to README.md
    with open('README.md', 'w', encoding='utf-8') as f:
        f.write('\n'.join(updated_lines))
    
    print("\n✅ README.md updated successfully!")

if __name__ == "__main__":
    main()
