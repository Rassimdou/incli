import requests 


class Uploader:
    def __init__(self, upload_url, cookies= None):
        self.upload_url = upload_url
        self.cookies = cookies or {}


    def upload(self, filename , content):
        files = {
            "file": (filename, content, "image/jpeg")
        }
        return requests.post(
            self.upload_url,
            files=files,
            cookies=self.cookies,
            allow_redirects=False
        )