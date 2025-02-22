import requests
import whois
import argparse
import csv
import json
import socket
import ssl
import hashlib
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from PIL import Image
import imagehash
from io import BytesIO

# OSINT Data Sources
BING_SEARCH_URL = "https://www.bing.com/search?q={query}"
URLHAUS_FEED = "https://urlhaus.abuse.ch/downloads/text_online/"
OPENPHISH_FEED = "https://openphish.com/feed.txt"

HEADERS = {"User-Agent": "Mozilla/5.0"}

# Define phishing-related keywords
PHISHING_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "password",
    "banking", "billing", "confirm", "credential", "reset", "authentication"
]

def bing_search(target):
    """Search Bing for potential phishing sites."""
    query = f"inurl:{target} -site:{target}"
    url = BING_SEARCH_URL.format(query=query.replace(" ", "+"))
    response = requests.get(url, headers=HEADERS)
    if response.status_code != 200:
        return []
    soup = BeautifulSoup(response.text, "html.parser")
    return list(set(link["href"] for link in soup.find_all("a", href=True) if "http" in link["href"]))

def check_urlhaus(target):
    """Check URLHaus phishing feeds."""
    response = requests.get(URLHAUS_FEED)
    return [url for url in response.text.split("\n") if target in url]

def check_openphish(target):
    """Check OpenPhish feeds."""
    response = requests.get(OPENPHISH_FEED)
    return [url for url in response.text.split("\n") if target in url]

def extract_html_content(url):
    """Fetch website content and extract text and metadata."""
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")

        # Extract visible text
        text = soup.get_text(separator=" ").lower()

        # Extract metadata
        meta_tags = {meta.get("name", "").lower(): meta.get("content", "").lower()
                     for meta in soup.find_all("meta") if meta.get("name")}

        return {"text": text, "meta": meta_tags}
    except:
        return None

def detect_phishing_content(content, original_domain):
    """Analyze website content for phishing indicators."""
    indicators = []
    
    # Check for phishing keywords
    for keyword in PHISHING_KEYWORDS:
        if keyword in content["text"]:
            indicators.append(f"Keyword Detected: {keyword}")

    # Check if original domain name is mentioned
    if original_domain in content["text"]:
        indicators.append(f"Mentions Original Domain: {original_domain}")

    # Compare metadata with suspicious patterns
    if "login" in content["meta"].get("title", "") or "secure" in content["meta"].get("title", ""):
        indicators.append("Suspicious Meta Title Detected")

    return indicators

def get_ssl_certificate_info(domain):
    """Retrieve SSL certificate issuer and subject details."""
    try:
        conn = socket.create_connection((domain, 443))
        context = ssl.create_default_context()
        with context.wrap_socket(conn, server_hostname=domain) as sock:
            cert = sock.getpeercert()
            return {"issuer": cert.get("issuer"), "subject": cert.get("subject")}
    except:
        return None

def hash_image_from_url(url):
    """Download image from URL and generate a perceptual hash."""
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        img = Image.open(BytesIO(response.content))
        return imagehash.phash(img)
    except:
        return None

def compare_logo_images(original_logo_url, suspicious_logo_url):
    """Compare logos using perceptual hashing."""
    original_hash = hash_image_from_url(original_logo_url)
    suspicious_hash = hash_image_from_url(suspicious_logo_url)

    if original_hash and suspicious_hash:
        difference = original_hash - suspicious_hash
        return difference
    return None

def correlate_results(domain, sources, original_domain):
    """Calculate risk score and classify threats, excluding the original domain."""
    if original_domain in domain:
        return None

    score = 0
    report = []

    if domain in sources["bing"]: 
        score += 10
        report.append("Found in Bing")
    if domain in sources["urlhaus"]: 
        score += 15
        report.append("Listed in URLHaus")
    if domain in sources["openphish"]: 
        score += 15
        report.append("Listed in OpenPhish")

    if score > 30:
        risk = "⚠️ High Risk - Confirmed Phishing"
    elif score > 15:
        risk = "⚠️ Suspicious - Needs Review"
    else:
        risk = "Low Risk - Likely Safe"

    return {"Domain": domain, "Risk Level": risk, "Score": score, "Sources": ", ".join(report)}

def main():
    parser = argparse.ArgumentParser(description="Detect phishing, typosquatting, and impersonating websites.")
    parser.add_argument("original_url", help="The official website to check for impersonators (e.g., landbank.com)")
    parser.add_argument("--logo", help="URL of the original website's logo for comparison", required=False)
    args = parser.parse_args()

    parsed_original = urlparse(args.original_url).netloc  
    print(f"\n🔍 Analyzing: {args.original_url}\n")

    # [1/5] Search for possible phishing domains
    print("🔎 [1/5] Running Bing search for possible phishing domains...")
    sources = {
        "bing": bing_search(args.original_url),
        "urlhaus": check_urlhaus(args.original_url),
        "openphish": check_openphish(args.original_url),
    }
    print(f"   Bing search found {len(sources['bing'])} results.")
    print(f"   URLHaus found {len(sources['urlhaus'])} matches.")
    print(f"   OpenPhish found {len(sources['openphish'])} reported domains.")

    # [2/5] Extract website content
    print("\n🔎 [2/5] Extracting website content and analyzing for phishing indicators...")
    results = [
        correlate_results(domain, sources, parsed_original) 
        for domain in sources["bing"] + sources["urlhaus"] + sources["openphish"]
    ]
    results = [r for r in results if r]  

    logo_check_performed = False
    logo_findings = []

    for result in results:
        domain = result["Domain"]

        # [3/5] Checking phishing indicators in extracted content
        print(f"🔎 [3/5] Analyzing phishing content on {domain}...")
        content = extract_html_content(domain)
        if content:
            phishing_indicators = detect_phishing_content(content, parsed_original)
            if phishing_indicators:
                result["Phishing Indicators"] = ", ".join(phishing_indicators)
                print(f"   ⚠️ Phishing indicators found: {', '.join(phishing_indicators)}")

        # [4/5] SSL certificate analysis
        print(f"🔎 [4/5] Checking SSL certificate for {domain}...")
        ssl_info = get_ssl_certificate_info(domain)
        if ssl_info:
            result["SSL Issuer"] = str(ssl_info["issuer"])
            result["SSL Subject"] = str(ssl_info["subject"])
            print(f"   SSL Issuer: {ssl_info['issuer']}")

        # [5/5] Logo Image Comparison (if provided)
        if args.logo:
            logo_check_performed = True
            print(f"🔎 [5/5] Comparing logos for {domain}...")
            logo_difference = compare_logo_images(args.logo, f"https://{domain}/favicon.ico")
            if logo_difference is not None and logo_difference < 10:
                result["Logo Similarity"] = "⚠️ Similar Logo Detected"
                logo_findings.append(f"⚠️ Similar logo detected on {domain}")
                print(f"   ⚠️ Similar logo detected with {domain}.")
    
    if not results:
        print("\nNo Findings. The domain appears safe.\n")
        print("**Scan Summary:**")
        print("- Bing, URLHaus, and OpenPhish were checked for phishing domains.")
        print("- Website content was analyzed for phishing-related text.")
        print("- SSL certificate was verified.")
        if args.logo:
            if logo_findings:
                print("- Logo similarity checked, suspicious findings detected.")
            else:
                print("- Logo similarity checked, no suspicious matches.")
        return

    print("\n🔎 **Phishing Detection Results:**")
    print("{:<60} {:<30} {:<20}".format("Domain", "Risk Level", "Indicators"))
    print("=" * 120)
    for result in results:
        print("{:<60} {:<30} {:<20}".format(result["Domain"], result["Risk Level"], result.get("Phishing Indicators", "N/A")))

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_filename = f"dupescan-{timestamp}.csv"

    with open(output_filename, "w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=["Domain", "Risk Level", "SSL Issuer", "SSL Subject", "Phishing Indicators", "Logo Similarity"])
        writer.writeheader()
        writer.writerows(results)

    print(f"\nResults saved to {output_filename}\n")

    print("**Scan Summary:**")
    print("- Bing, URLHaus, and OpenPhish were checked for phishing domains.")
    print("- Website content was analyzed for phishing-related text.")
    print("- SSL certificate was verified.")
    if args.logo:
        if logo_findings:
            print("- Logo similarity checked, suspicious findings detected.")
        else:
            print("- Logo similarity checked, no suspicious matches.")

    print("\nScan complete!")




if __name__ == "__main__":
    main()
