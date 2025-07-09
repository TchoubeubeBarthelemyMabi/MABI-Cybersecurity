import requests, socket
from urllib.parse import urlparse

COMMON_PATHS = ['/admin', '/login', '/phpmyadmin', '/config', '/setup', '/dashboard']

def scan_site(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path

    report = {
        'headers': {},
        'subdomains': [],
        'sensitive_paths': [],
        'sql_injection': None,
        'open_ports': [],
        'conclusion': "",
        'vuln_count': 0
    }

    try:
        r = requests.get(url, timeout=5)
        hdr = r.headers
        for h in ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options']:
            if h in hdr:
                report['headers'][h] = '✅'
            else:
                report['headers'][h] = '❌'
                report['vuln_count'] += 1
        report['headers']['Server'] = hdr.get('Server', 'Inconnu')
    except:
        report['headers']['error'] = "Analyse impossible."

    for sub in ['www', 'mail', 'ftp']:
        try:
            resp = requests.get(f"http://{sub}.{domain}", timeout=3)
            if resp.status_code < 400:
                report['subdomains'].append(f"{sub}.{domain}")
        except:
            pass

    for path in COMMON_PATHS:
        try:
            resp = requests.get(url.rstrip('/') + path, timeout=3)
            if resp.status_code == 200:
                report['sensitive_paths'].append(path)
                report['vuln_count'] += 1
        except:
            pass

    try:
        resp = requests.get(url, params={'id': "' OR '1'='1"}, timeout=5)
        txt = resp.text.lower()
        report['sql_injection'] = '❌ Vulnérable' if 'sql' in txt or 'error' in txt else '✅ Non vulnérable'
        if '❌' in report['sql_injection']:
            report['vuln_count'] += 1
    except:
        report['sql_injection'] = '⚠️ Test impossible'

    for port in [21, 22, 80, 443, 3306]:
        try:
            sock = socket.create_connection((domain, port), timeout=1)
            report['open_ports'].append(port)
            sock.close()
        except:
            pass

    return report