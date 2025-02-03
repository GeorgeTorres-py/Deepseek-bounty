import argparse
import re
import requests
import aiohttp
import asyncio
from urllib.parse import urlparse
import nmap
import sqlmap
import os
import hashlib
from bs4 import BeautifulSoup

class DeepSeekBounty:
    def __init__(self, target, api_key=None):
        self.target = target
        self.api_key = api_key
        self.session = requests.Session()
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) DeepSeekBounty/1.0'}
        self.vulnerabilities = []

    async def network_mapper(self):
        """Perform network mapping using nmap"""
        print(f"[+] Scanning network: {self.target}")
        scanner = nmap.PortScanner()
        scanner.scan(self.target, arguments='-sV -T4')
        return scanner.csv()

    async def directory_fuzzer(self, wordlist="common_dirs.txt"):
        """Discover hidden directories"""
        print(f"[+] Fuzzing directories on: {self.target}")
        with open(wordlist) as f:
            directories = f.read().splitlines()
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for dir in directories:
                url = f"{self.target}/{dir}"
                tasks.append(self._check_directory(session, url))
            
            results = await asyncio.gather(*tasks)
            return [result for result in results if result]

    async def _check_directory(self, session, url):
        try:
            async with session.get(url, headers=self.headers) as response:
                if response.status == 200:
                    return url
        except:
            return None

    def api_key_scanner(self, response):
        """Check for exposed API keys"""
        patterns = {
            'google_api': r'AIza[0-9A-Za-z-_]{35}',
            'aws_access_key_id': r'AKIA[0-9A-Z]{16}',
            'stripe': r'sk_live_[0-9a-zA-Z]{24}'
        }
        
        found_keys = []
        for service, pattern in patterns.items():
            matches = re.findall(pattern, response.text)
            if matches:
                found_keys.append((service, matches))
        return found_keys

    async def sql_injection_test(self, url):
        """Test for SQL injection vulnerabilities"""
        print(f"[+] Testing SQLi on: {url}")
        # Integrate with sqlmap API (simplified example)
        report = sqlmap.scan(url, level=5, risk=3)
        return report

    def open_redirect_test(self, url):
        """Test for open redirect vulnerabilities"""
        test_params = {
            'redirect': 'https://evil.com',
            'url': '//evil.com',
            'next': 'http://malicious.site'
        }
        
        vulnerable_params = []
        for param, payload in test_params.items():
            test_url = f"{url}?{param}={payload}"
            response = self.session.get(test_url, allow_redirects=False)
            if 300 <= response.status_code < 400:
                if 'evil.com' in response.headers.get('Location', '') or \
                   'malicious.site' in response.headers.get('Location', ''):
                    vulnerable_params.append(param)
        return vulnerable_params

    async def deepseek_search(self, query):
        """Integrate with DeepSeek's search API"""
        print("[+] Searching DeepSeek for target information")
        # Example API call (replace with actual DeepSeek API integration)
        api_url = "https://api.deepseek.com/v1/search"
        params = {'q': query, 'api_key': self.api_key}
        response = self.session.get(api_url, params=params)
        return response.json()

    async def full_scan(self):
        """Run complete security assessment"""
        report = {
            'network': await self.network_mapper(),
            'directories': await self.directory_fuzzer(),
            'vulnerabilities': self.vulnerabilities
        }
        
        # Additional checks
        homepage = self.session.get(self.target)
        report['exposed_keys'] = self.api_key_scanner(homepage)
        
        return report

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DeepSeekBounty - Bug Bounty Toolkit")
    parser.add_argument("-t", "--target", required=True, help="Target URL or IP")
    parser.add_argument("-a", "--api-key", help="DeepSeek API key")
    args = parser.parse_args()

    scanner = DeepSeekBounty(args.target, args.api_key)
    loop = asyncio.get_event_loop()
    report = loop.run_until_complete(scanner.full_scan())
    
    print("\n[+] Scan Report:")
    print(f"Open Ports: {report['network']}")
    print(f"Found Directories: {report['directories']}")
    print(f"Exposed API Keys: {report['exposed_keys']}")
