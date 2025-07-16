import requests
import socket
from urllib.parse import urlparse

# Chemins sensibles souvent exposés aux erreurs de configuration
COMMON_PATHS = ['/admin', '/login', '/phpmyadmin', '/config', '/setup', '/dashboard']

def scan_site(url):
    # Préparation et validation de l’URL
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

    # Vérification des headers de sécurité
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        for header in ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options']:
            if header in headers:
                report['headers'][header] = '✅'
            else:
                report['headers'][header] = '❌'
                report['vuln_count'] += 1
        report['headers']['Server'] = headers.get('Server', 'Inconnu')
    except Exception as e:
        report['headers']['error'] = f"Analyse impossible : {str(e)}"
        report['vuln_count'] += 1

    # Sous-domaines communs accessibles
    for sub in ['www', 'mail', 'ftp']:
        subdomain = f"{sub}.{domain}"
        try:
            resp = requests.get(f"http://{subdomain}", timeout=3)
            if resp.status_code < 400:
                report['subdomains'].append(subdomain)
        except:
            continue

    # Détection de chemins sensibles
    for path in COMMON_PATHS:
        full_path = url.rstrip('/') + path
        try:
            resp = requests.get(full_path, timeout=3)
            if resp.status_code == 200:
                report['sensitive_paths'].append(path)
                report['vuln_count'] += 1
        except:
            continue

    # Test simple d’injection SQL
    try:
        resp = requests.get(url, params={'id': "' OR '1'='1"}, timeout=5)
        content = resp.text.lower()
        if 'sql' in content or 'error' in content or 'query' in content:
            report['sql_injection'] = '❌ Vulnérable'
            report['vuln_count'] += 1
        else:
            report['sql_injection'] = '✅ Non vulnérable'
    except Exception:
        report['sql_injection'] = '⚠️ Test impossible'

    # Vérification de ports communs ouverts
    for port in [21, 22, 80, 443, 3306]:
        try:
            sock = socket.create_connection((domain, port), timeout=1)
            report['open_ports'].append(port)
            sock.close()
        except:
            continue

    return report
