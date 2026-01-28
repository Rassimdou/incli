import requests 


class Fetcher:
    def __init__(self , cookies=None):
        self.cookies = cookies or {} 


    def get(self, url):
        return requests.get(url, cookies=self.cookies)