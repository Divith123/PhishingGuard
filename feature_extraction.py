import re
import ipaddress
import whois as whois
import requests
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from tld import get_tld
from datetime import datetime

print("#1  Extracting Features")

def isIP(url):  #1
        try:
            ipaddress.ip_address(url)
            ip = 1
        except:
            ip = -1
        return ip


def LongURL(url): #2
        if len(url) < 54:
            return -1           
        else:
            return 1 


def shortURL(url): #3
        shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"
        match=re.search(shortening_services,url)
        if match:
            return 1
        else:
            return -1
        
def check_symbol_at(url): #4
    # Check if the "@" symbol is present in the URL
    return  1 if "@" in url else -1

def check_prefix_suffix(url): #5
    # Check if the URL contains prefixes or suffixes
    return  1 if ("-" or '.') in url else -1

def check_redirecting(url): #6
    # Check if the URL contains multiple forward slashes
    return 1 if "//" in url else -1

def check_subdomains(url): #7
    # Count the number of subdomains in the URL
    subdomains = url.split('.')[:-1]
    return 1 if len(subdomains) > 3 else -1

def check_https(url): #8
    # Check if the URL uses HTTPS
    return -1 if "https://" in url else 1

def get_domain_registration_date(url): #9
    try:
        domain_name = url.split("//")[-1].split("/")[0].split('?')[0].split(':')[0]
        domain_info = whois.whois(domain_name)

        if domain_info.creation_date:
            if isinstance(domain_info.creation_date, list):
                creation_date = domain_info.creation_date[0]
                if creation_date.year > 2020:
                    return 1
            else:
                if domain_info.creation_date.year > 2020:
                    return 1
                else:
                    return -1
        else:
            return -1
    
    except Exception as e:
        print("Error:", e)
        return -1



def check_favicon_existence(url): #10
    try:
        response = requests.get(url)
        
        # Check if the response contains a favicon
        if 'favicon.ico' in response.text:
            return -1
        else:
            return 1
    
    except Exception as e:
        print("Error on favicon get:", e)
        return 1
    
    

def check_nonstandard_ports(domain): #11
    common_ports = [80, 443]  # common HTTP and HTTPS ports
    
    for port in common_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)  # timeout for connection attempt
                s.connect((domain, port))
                return -1
        except Exception as e:
            return 1
        
    
def check_domain_in_https_url(url, domain): #12
    parsed_url = urlparse(url)
    
    # Check if the URL scheme is HTTPS
    if parsed_url.scheme != 'https':
        return -1

    url_domain = parsed_url.netloc
    if domain in url_domain:
        return -1
    else:
        return 1
    
def is_request_url(url): #13
    request_url_pattern = r"https://.*?/request/.*"
    
    # Checking if the URL matches the pattern
    if re.match(request_url_pattern, url):
        return 1
    else:
        return -1


def check_anchor_url(url): #14
    # Check if anchor tags are present in the URL
    return 1 if "#" in url else -1

def links_from_script_tags(url): #15
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        
        script_tags = soup.find_all('script')
        links = []
        for script in script_tags:
            script_content = script.string
            if script_content:
                urls = re.findall(r'(https?://\S+)', script_content)
                links.extend(urls)
        
        if len(links)> 2:
            return 1
        else:
            return -1
    else:
        print("Error fetching URL:", response.status_code)
        return 1
    

def check_server_side_handler(url): #16

    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        if not forms:
            return 1
        else:
            for form in forms:
                action = form.get('action')
                method = form.get('method')
                
                if action and method == 'post':
                    return -1
                else:
                    return 1

    else:
        print(f"Failed to fetch webpage: {url}")
        return 1




def check_info_email(url): #17
    # Checking if an email address is present in the URL
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return 1 if re.search(email_pattern, url) else -1


def is_abnormal_url(url): #18
    # Checking for long sequences of random characters
    if re.match(r'.*([a-zA-Z0-9])\1{8,}', url):
        return 1
    
    # Check for unusual domain names or subdomains
    domain = urlparse(url).netloc
    tld = get_tld(url)
    if len(domain) > 50 or len(tld) > 10:
        return 1
    
    # Check for excessive redirections
    try:
        response = requests.get(url, allow_redirects=False)
        if response.status_code in [301, 302] and 'Location' in response.headers:
            return 1
    except Exception as e:
        pass
    
    # Check for suspicious TLDs
    suspicious_tlds = [
    '.tk', '.pw', '.info', '.biz', '.xyz', '.top', '.club', '.work', '.online',
    '.site', '.website', '.space', '.click', '.link', '.download', '.trade',
    '.review', '.party', '.win', '.stream', '.gdn', '.racing', '.science', 
    '.gq', '.icu', '.ooo', '.mobi', '.fun', '.buzz', '.kim'
]  
    if tld in suspicious_tlds:
        return 1
    
    # Check for unusual protocols
    if not url.startswith('http://') and not url.startswith('https://'):
        return 1
    
    # If none of the above conditions match, return -1 (not abnormal)
    return -1

def check_url_forwarding(url): #19
    try:
        response = requests.get(url, allow_redirects=True)
        final_url = response.url
        if final_url != url:
            return 1
        else:
            return -1
    except requests.RequestException as e:
        print("Error:", e)

    
def check_status_bar_cust(url): #20
    try:
        response = requests.get(url)
        if response.status_code == 200:
            html_content = response.text
            
            status_bar_pattern = r'onmouseover=["\'](.*?)["\']'
            
            return 1 if re.search(status_bar_pattern, html_content) else -1
        else:
            print("Error fetching URL:", response.status_code)
            return 1
    except Exception as e:
        print("Error:", e)
        return 1



def check_right_click_disabled(url): #21
    try:
        response = requests.get(url)
        response.raise_for_status()  

        soup = BeautifulSoup(response.text, 'html.parser')

        scripts = soup.find_all('script')
        for script in scripts:
            if "oncontextmenu" in script.get_text():
                return 1 
            else:
                return -1
        return -1  
    except requests.exceptions.RequestException as e:
        print("Error:", e)
        return 1  



def check_popup_windows(url): #22
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for 4xx and 5xx status codes

        patterns = [
            r'window\.open\(',  # JavaScript function to open a new window
            r'popup\(',         # Commonly named JavaScript function for popups
            r'onbeforeunload=', # Event handler for before unloading (might be used for popups)
            r'confirm\(',       # JavaScript function for confirmation dialogs (sometimes used for popups)
        ]
        for pattern in patterns:
            if re.search(pattern, response.text):
                return 1 
        return -1  
    except requests.exceptions.RequestException as e:
        print("Error:", e)
        return 1 


def check_iframe_redirection(url): #23
    try:
        response = requests.get(url)
        response.raise_for_status()  
        soup = BeautifulSoup(response.text, 'html.parser')

        iframes = soup.find_all('iframe')
        for iframe in iframes:
            src = iframe.get('src')
            if src:  
                return 1 
            else:
                return -1
        return -1  
    except requests.exceptions.RequestException as e:
        print("Error:", e)
        return 1 
    

def get_domain_age(url): #24
    try:
        domain_name = url.split("//")[-1].split("/")[0].split('?')[0].split(':')[0]
        domain_info = whois.whois(domain_name)
        creation_date = domain_info.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, datetime):
            age = (datetime.now() - creation_date).days
            return -1 if age < 200 else 1
        else:
            return 1  
    except Exception as e:
        print("Error:", e)
        return None  


def check_dns_records(url): #25
    try:
        domain_name = url.split("//")[-1].split("/")[0].split('?')[0].split(':')[0]
        ip_addresses = socket.gethostbyname_ex(domain_name)

        if ip_addresses:
            return -1  
        else:
            return 1  
    except Exception as e:
        print("Error:", e)
        return None  


def is_indexed(url): #26
    try:
        response = requests.get(f"https://www.google.com/search?q=site:{url}")
        if response.status_code == 200:
            return -1
        else:
            return 1
    except Exception as e:
        return f"An error occurred: {str(e)}"




def extract_url(url):
    try:
        results = []
        results.append(isIP(url)) #1
        results.append(LongURL(url)) #2
        results.append(shortURL(url)) #3
        results.append(check_symbol_at(url)) #4
        results.append(check_redirecting(url))#5
        results.append(check_prefix_suffix(url)) #6
        results.append(check_subdomains(url)) #7
        results.append(check_https(url)) #8
        results.append(get_domain_registration_date(url)) #9
        results.append(check_favicon_existence(url)) #10
        results.append(check_nonstandard_ports(urlparse(url).netloc)) #11
        results.append(check_domain_in_https_url(url, urlparse(url).netloc)) #12
        results.append(is_request_url(url)) #13
        results.append(check_anchor_url(url)) #14
        results.append(links_from_script_tags(url)) #15
        results.append(check_server_side_handler(url)) #16
        results.append(check_info_email(url)) #17
        results.append(is_abnormal_url(url)) #18
        results.append(check_url_forwarding(url)) #19
        results.append(check_status_bar_cust(url)) #20
        results.append(check_right_click_disabled(url)) #21
        results.append(check_popup_windows(url)) #22
        results.append(check_iframe_redirection(url)) #23
        results.append(get_domain_age((url))) #24
        results.append(check_dns_records(url)) #25
        results.append(is_indexed(url)) #26
        
        print("#2  Extracted Features for  "+ url)
        results = [-1 if x is None else x for x in results]
        print(results)
        return results
    
    except Exception as e:
        print("Error:", e)
        pass