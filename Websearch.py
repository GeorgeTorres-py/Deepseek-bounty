class WebSearcher:
    def __init__(self):
        self.search_engines = [
            "https://google.com/search?q=",
            "https://api.deepseek.com/v1/search?q="
        ]

    def dorking(self, target, filetype="pdf"):
        """Find sensitive files using search engines"""
        query = f"site:{target} filetype:{filetype}"
        return self._search(query)

    def _search(self, query):
        results = []
        for engine in self.search_engines:
            response = requests.get(engine + query)
            soup = BeautifulSoup(response.text, 'html.parser')
            # Add parser for each search engine
            results.extend(self._parse_results(soup))
        return results
