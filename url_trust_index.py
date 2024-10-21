from urllib.parse import urlparse
import sitesniffer
from datetime import datetime
import requests
import whois


def calculate_uti(url):
    confidence_score = 0

    try:
        ssl_info = sitesniffer.get_ssl_info(url)
        current_date = datetime.utcnow()

        # 1. Check SSL Certificate Validity
        try:
            not_before = datetime.strptime(ssl_info['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(ssl_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
            if not_before <= current_date <= not_after:
                confidence_score += 0.2
        except KeyError:
            pass

        # 2. Check if the Issuer is Recognized
        recognized_issuers = set([
            'Amazon', 'Comodo', 'DigiCert', 'Symantec', 'GlobalSign', 'Let\'s Encrypt', 'GoDaddy', 'Entrust',
            'Thawte', 'GeoTrust', 'RapidSSL', 'Trustwave', 'Network Solutions', 'Namecheap', 'SSL.com', 'Buypass',
            'Sectigo', 'IdenTrust', 'TrustCor', 'QuoVadis', 'Actalis', 'Certum', 'WISeKey', 'SwissSign', 'StartCom',
            'WoSign', 'Certum', 'TWCA', 'SecureTrust', 'USERTrust', 'Sectigo', 'AC Camerfirma', 'TrustAsia',
            'Trustico', 'GMO GlobalSign', 'Global Chambersign', 'E-Tugra', 'Cambridge University', 'Telia',
            'Microsec', 'Certigna', 'GlobalSign', 'AffirmTrust', 'MSCTrustgate', 'Buypass', 'Dhimyotis', 'CA Disig',
            'T-Systems', 'ACCV', 'Trustis', 'CAcert', 'Hongkong Post', 'Disig', 'GlobalSign', 'Asseco', 'Certum',
            'LuxTrust', 'PKIoverheid', 'SK ID Solutions', 'GeoTrust', 'DocuSign', 'Izenpe', 'Serasa', 'Unizeto',
            'CNNIC', 'RSA Security', 'SZAFIR', 'ACT', 'Trustwave'
        ])

        try:
            issuer = ssl_info['issuer'][0][0][1]
            if issuer in recognized_issuers:
                confidence_score += 0.2
        except (KeyError, IndexError):
            pass

        # 3. Check if Domain is in Subject
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        try:
            subject = ssl_info['subject'][0][0][1]
            if domain in subject:
                confidence_score += 0.2
        except (KeyError, IndexError):
            pass

        # 4. Check Subject Alternative Names (SAN)
        try:
            san_domains = [san[1] for san in ssl_info.get('subjectAltName', [])]
            if domain in san_domains:
                confidence_score += 0.2
        except KeyError:
            pass

        # 5. Check OCSP and CRL
        try:
            if ssl_info.get('OCSP') and ssl_info.get('crlDistributionPoints'):
                confidence_score += 0.2
        except KeyError:
            pass

    except Exception as e:
        print(f"SSL Info Error: {e}")
        confidence_score -= 2

    # 6. Check OpenPage Rank Score
    try:
        base_url = 'https://openpagerank.com/api/v1.0/'
        endpoint = 'getPageRank'
        url = base_url + endpoint
        params = {'domains[]': domain}
        headers = {'API-OPR': 'API-KEY'}  # Replace with actual API key

        response = requests.get(url, params=params, headers=headers)
        if response.status_code == 200:
            data = response.json().get('response', [])
            for result in data:
                if result.get('status_code') == 200 and result.get('page_rank_decimal', 0) > 4:
                    confidence_score += 0.2
        else:
            print(f"PageRank Error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"OpenPageRank Error: {e}")

    # 7. Check Domain Age
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date and (current_date - creation_date).days > 200:
            confidence_score += 0.2
    except whois.parser.PywhoisError as e:
        print(f"Domain Whois Error: {e}")

    # 8. Check if Domain Supports HTTPS
    try:
        response = requests.get(f"https://{domain}")
        if response.status_code == 200:
            confidence_score += 0.2
    except requests.RequestException as e:
        print(f"HTTPS Check Error: {e}")

    # Final Confidence Score Calculation
    return round((confidence_score / 1.4) * 9 + 1, 2)
