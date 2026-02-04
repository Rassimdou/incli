import requests 


class Fetcher:
    def __init__(self , cookies=None):
        self.cookies = cookies or {} 
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

    def get(self, url):
        return requests.get(url, cookies=self.cookies, headers=self.headers)