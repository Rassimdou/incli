import requests 
import re
from typing import Optional


class Uploader:
    def __init__(self, upload_url, cookies= None):
        self.upload_url = upload_url
        self.cookies = cookies or {}
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        self.session = requests.Session()
        self.session.cookies.update(self.cookies)
        self.session.headers.update(self.headers)
        
        self.discovered_field = None
        self.extra_data = {}

    def _discover_field_and_csrf(self) -> tuple:
        """Fetch the upload page and discover form fields and CSRF"""
        csrf = None
        
        try:
            # Try both the upload URL and its parent directory
            pages_to_check = [self.upload_url]
            parent = self.upload_url.rsplit('/', 1)[0]
            if parent not in pages_to_check:
                pages_to_check.append(parent)
            
            for url in pages_to_check:
                response = self.session.get(url)
                if response.status_code != 200: continue
                
                # CSRF extraction
                csrf_match = re.search(r'name="csrf"\s+value="([^"]+)"', response.text)
                if not csrf: csrf = csrf_match.group(1) if csrf_match else None
                
                # Field discovery (naive)
                if not self.discovered_field:
                    # Look for input type=file
                    field_match = re.search(r'type="file"\s+name="([^"]+)"', response.text)
                    if field_match:
                        self.discovered_field = field_match.group(1)
                    
                    # Look for other hidden fields we might need
                    hidden_fields = re.findall(r'type="hidden"\s+name="([^"]+)"\s+value="([^"]*)"', response.text)
                    for name, value in hidden_fields:
                        if name != "csrf" and name not in self.extra_data:
                            self.extra_data[name] = value

                if self.discovered_field and csrf: break
                
        except Exception as e:
            print(f"      [!] Discovery error: {e}")
            
        return csrf

    def upload(self, filename , content):
        csrf = self._discover_field_and_csrf()
        
        # Use discovered field or fall back to defaults
        field_name = self.discovered_field or "file"
        if not self.discovered_field and "web-security-academy" in self.upload_url:
            field_name = "avatar"
        
        files = {
            field_name: (filename, content, "image/jpeg")
        }
        
        data = self.extra_data.copy()
        if csrf:
            data["csrf"] = csrf
        
        return self.session.post(
            self.upload_url,
            files=files,
            data=data,
            allow_redirects=False
        )
