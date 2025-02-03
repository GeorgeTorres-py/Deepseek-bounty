class APITester:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.auth_methods = ['Bearer', 'Basic', 'JWT']

    def test_endpoint(self):
        tests = {
            'authentication': self.test_auth(),
            'rate_limiting': self.test_rate_limits(),
            'injection': self.test_injections()
        }
        return tests

    def test_rate_limits(self):
        requests = []
        for _ in range(100):
            response = requests.get(self.endpoint)
            requests.append(response.status_code)
        return any(429 in requests)

    def test_auth(self):
        vulnerabilities = []
        for method in self.auth_methods:
            headers = {'Authorization': f'{method} invalid_token'}
            response = requests.get(self.endpoint, headers=headers)
            if response.status_code == 200:
                vulnerabilities.append(f'Broken {method} auth')
        return vulnerabilities
