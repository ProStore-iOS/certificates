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

def convert_to_dd_mm_yy(date_str):
    """Convert date to DD/MM/YY HH:mm format."""
    # Remove any timezone indicators or extra text
    date_str = re.sub(r'\(.*?\)', '', date_str).strip()
    
    # List of possible date formats to try
    date_formats = [
        "%m/%d/%y %H:%M",    # 08/02/23 06:07
        "%d/%m/%y %H:%M",    # 02/08/23 06:07
        "%Y/%m/%d %H:%M",    # 2023/08/02 06:07
        "%Y-%m-%d %H:%M:%S", # 2023-08-02 06:07:00
        "%d %b %Y %H:%M",    # 02 Aug 2023 06:07
        "%b %d, %Y %H:%M",   # Aug 02, 2023 06:07
        "%m/%d/%Y %H:%M",    # 08/02/2023 06:07
        "%d/%m/%Y %H:%M",    # 02/08/2023 06:07
    ]
    
    for fmt in date_formats:
        try:
            dt = datetime.strptime(date_str, fmt)
            # Convert to DD/MM/YY HH:mm format
            return dt.strftime("%d/%m/%y %H:%M")
        except ValueError:
            continue
    
    # If no format matches, try to extract date parts with regex
    date_patterns = [
        r'(\d{1,2})/(\d{1,2})/(\d{2,4})\s+(\d{1,2}):(\d{2})',  # MM/DD/YY HH:MM or DD/MM/YY HH:MM
        r'(\d{1,2})/(\d{1,2})/(\d{2,4})',  # Just date without time
    ]
    
    for pattern in date_patterns:
        match = re.search(pattern, date_str)
        if match:
            try:
                if len(match.groups()) >= 5:  # Has time
                    month, day, year, hour, minute = match.groups()[:5]
                else:  # Only date
                    month, day, year = match.groups()[:3]
                    hour, minute = "00", "00"
                
                # Determine if format is MM/DD or DD/MM
                if int(month) > 12:  # Month can't be >12, so this must be DD/MM
                    day, month = month, day
                
                # Convert 2-digit year to proper format
                if len(year) == 2:
                    year = int(year)
                    if year < 50:  # 00-49 = 2000-2049
                        year = 2000 + year
                    else:  # 50-99 = 1950-1999
                        year = 1900 + year
                else:
                    year = int(year)
                
                dt = datetime(year, int(month), int(day), int(hour), int(minute))
                return dt.strftime("%d/%m/%y %H:%M")
            except:
                pass
    
    # If all else fails, return original
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
        password = "nezushub.vip"
    
    try:
        with requests.Session() as session:
            token = get_token(session)
            html = submit_check(session, token, p12_path, password, mp_path)
            data = parse_html(html)
            
            status = data.get("binding_certificate_1", {}).get("status", "Unknown")
            effective = data.get("mobileprovision", {}).get("effective", "Unknown")
            expiration = data.get("mobileprovision", {}).get("expiration", "Unknown")
            
            # Convert dates to DD/MM/YY HH:mm format
            if effective != "Unknown":
                effective = convert_to_dd_mm_yy(effective)
            if expiration != "Unknown":
                expiration = convert_to_dd_mm_yy(expiration)
            
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
        cells = [cell.strip() for cell in line.split('|')[1:-1]]
        
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
        
        # Update status (preserve emoji formatting)
        if cert.get('status', '').lower() == 'valid':
            new_status = '✅ Signed'
        elif cert.get('status', '').lower() == 'revoked':
            new_status = '❌ Revoked'
        else:
            # Keep existing status if not determined
            new_status = row_parts[3].strip()
        
        # Update dates, use existing values if new ones are Unknown
        valid_from = cert.get('valid_from', 'Unknown')
        if valid_from == 'Unknown':
            valid_from = row_parts[4].strip()
        
        valid_to = cert.get('valid_to', 'Unknown')
        if valid_to == 'Unknown':
            valid_to = row_parts[5].strip()
        
        # Reconstruct row with proper spacing
        row_parts[3] = f" {new_status} "
        row_parts[4] = f" {valid_from} "
        row_parts[5] = f" {valid_to} "
        
        # Ensure we have the right number of columns
        if len(row_parts) > 7:  # Includes download link
            row_parts[6] = f" {cert.get('download', row_parts[6].strip())} "
        
        updated_lines[idx] = '|'.join(row_parts)
    
    return updated_lines

def update_recommended_cert(lines, certificates):
    """Update the recommended certificate section."""
    for i, line in enumerate(lines):
        if 'Recommend Certificate' in line and i + 1 < len(lines):
            next_line = lines[i + 1].strip()
            if 'China Telecommunications Corporation V2' in next_line:
                for cert in certificates:
                    if 'China Telecommunications Corporation V2' in cert.get('company', ''):
                        status = cert.get('status', '').lower()
                        if status == 'valid':
                            lines[i + 1] = f"**China Telecommunications Corporation V2 - ✅ Signed**"
                        else:
                            lines[i + 1] = f"**China Telecommunications Corporation V2 - ❌ Revoked**"
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
            # Keep existing values
            updated_certs.append(cert_info)
    
    # Update the README content
    updated_lines = update_readme_table(updated_certs, lines)
    updated_lines = update_recommended_cert(updated_lines, updated_certs)
    
    # Write back to README.md
    with open('README.md', 'w', encoding='utf-8') as f:
        f.write('\n'.join(updated_lines))
    
    print("\n✅ README.md updated successfully!")

if __name__ == "__main__":
    main()
