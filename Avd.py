class VulnerabilityScanner:
    def __init__(self, target):
        self.target = target
        self.payloads = {
            'xss': ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>'],
            'ssti': ['{{7*7}}', '${7*7}'],
            'lfi': ['../../etc/passwd', '....//....//etc/passwd']
        }

    def test_injections(self):
        results = {}
        for vuln_type, payloads in self.payloads.items():
            results[vuln_type] = []
            for payload in payloads:
                response = requests.get(f"{self.target}?param={payload}")
                if self._detect_vulnerability(response, vuln_type):
                    results[vuln_type].append(payload)
        return results

    def _detect_vulnerability(self, response, vuln_type):
        detection_methods = {
            'xss': lambda r: any(payload in r.text for payload in self.payloads['xss']),
            'ssti': lambda r: '49' in r.text,
            'lfi': lambda r: 'root:x' in r.text
        }
        return detection_methods[vuln_type](response)
