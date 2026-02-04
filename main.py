
import argparse
import sys
import os
import requests
import re
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


from network.fetcher import Fetcher
from network.uploader import Uploader
from models.attack_context import AttackContext
from intelligence.detector import IntelligenceDirector


class LabAuthenticator:
    """
    Helper to authenticate with PortSwigger labs
    """
    
    def __init__(self, base_url: str, username: str = "wiener", password: str = "peter"):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })
    
    def login(self) -> Optional[str]:
        """
        Login and get session cookie
        
        Returns:
            Session cookie value or None
        """
        print(f"[*] Authenticating as {self.username}...")
        
     
        login_url = f"{self.base_url}/login"
        
        try:
            response = self.session.get(login_url)
            print(f"[*] GET {login_url} - Status: {response.status_code}")
            csrf_token = self._extract_csrf(response.text)
            
            if not csrf_token:
                print("[!] Could not extract CSRF token")
                return None
            
            print(f"[*] Extracted CSRF token: {csrf_token}")
            
          
            data = {
                "csrf": csrf_token,
                "username": self.username,
                "password": self.password
            }
            
            response = self.session.post(
                login_url, 
                data=data, 
                headers={
                    "Referer": login_url,
                    "Origin": self.base_url,
                    "Content-Type": "application/x-www-form-urlencoded"
                }, 
                allow_redirects=False
            )
            
            if response.status_code == 302:
        
                session_cookie = self.session.cookies.get('session')
                print(f"[+] Authenticated successfully")
                return session_cookie
            else:
                print(f"[!] Authentication failed (HTTP {response.status_code})")
                if response.text:
                    print(f"    Response: {response.text[:200]}...")
                return None
                
        except Exception as e:
            print(f"[!] Authentication error: {e}")
            return None
    
    def _extract_csrf(self, html: str) -> Optional[str]:
        """Extract CSRF token from HTML"""
        match = re.search(r'name="csrf"\s+value="([^"]+)"', html)
        return match.group(1) if match else None


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Intelligent File Upload Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # With manual session cookie
  %(prog)s -u https://target.com/upload --cookie "session=abc123"
  
  # Auto-login for PortSwigger lab
  %(prog)s -u https://LAB-ID.web-security-academy.net/my-account/avatar --auto-login
  
  # With custom credentials
  %(prog)s -u https://target.com/upload --username admin --password pass123
        """
    )
    

    parser.add_argument('-u', '--url',
                       required=True,
                       help='Upload endpoint URL')
    

    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument('--cookie',
                           help='Session cookie value (e.g., "session=abc123")')
    auth_group.add_argument('--auto-login',
                           action='store_true',
                           help='Automatically login (PortSwigger labs)')
    
    parser.add_argument('--username',
                       default='wiener',
                       help='Username for auto-login (default: wiener)')
    
    parser.add_argument('--password',
                       default='peter',
                       help='Password for auto-login (default: peter)')
    

    parser.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Verbose output')
    
    parser.add_argument('--base-url',
                       help='Base URL (auto-detected if not provided)')
    
    return parser.parse_args()


def extract_base_url(url: str) -> str:
    """Extract base URL from upload URL"""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def main():
    """Main entry point"""
    args = parse_arguments()
    
    print("="*70)
    print("INTELLIGENT FILE UPLOAD VULNERABILITY SCANNER")
    print("SQLMap-level Intelligence | Adaptive Strategy Selection")
    print("="*70)
    print()
    

    base_url = args.base_url or extract_base_url(args.url)
    
    print(f"[*] Target: {args.url}")
    print(f"[*] Base URL: {base_url}")
    print()
    

    cookies = {}
    
    if args.auto_login:

        authenticator = LabAuthenticator(base_url, args.username, args.password)
        session_cookie = authenticator.login()
        
        if not session_cookie:
            print("[!] Authentication failed")
            sys.exit(1)
        
        cookies['session'] = session_cookie
        print()
    
    elif args.cookie:

        if '=' in args.cookie:
            name, value = args.cookie.split('=', 1)
            cookies[name] = value
        else:
            print("[!] Invalid cookie format. Use: --cookie 'session=value'")
            sys.exit(1)
        print(f"[*] Using provided session cookie")
        print()
    
    else:
        print("[!] No authentication provided. Use --cookie or --auto-login")
        print("    Continuing without authentication (may fail)...")
        print()
    

    print("[*] Initializing intelligence components...")
    
    try:
      
        uploader = Uploader(upload_url=args.url, cookies=cookies)
        fetcher = Fetcher(cookies=cookies)
        
  
        context = AttackContext(
            target_url=base_url,
            parameter="file"
        )
        

        director = IntelligenceDirector(context, uploader, fetcher)
        
        print("[+] Components initialized")
        print()
        
    except Exception as e:
        print(f"[!] Initialization error: {e}")
        sys.exit(1)
    
   
    try:
        result = director.run_intelligent_scan()
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)
    
    except Exception as e:
        print(f"\n[!] Scan error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    
    
    print("\n" + "="*70)
    print("SCAN RESULTS")
    print("="*70)
    print()
    
    if result.vulnerabilities_found:
        print("[+] VULNERABLE!")
        print()
        print(f"    Technique: {result.successful_strategy}")
        
        if result.secret_extracted:
            print(f"    Secret: {result.secret_extracted}")
            print()
            print("    -> Copy the secret above and submit it to solve the lab!")
        
        print()
        print(f"    Statistics:")
        print(f"      - Observations: {result.observations_count}")
        print(f"      - Strategies Tried: {result.strategies_tried}")
        
    
        if args.verbose:
            print()
            print(director.explain_intelligence())
        
        sys.exit(0)
    
    else:
        print("[-] No vulnerabilities found")
        print()
        print(f"    Statistics:")
        print(f"      - Observations: {result.observations_count}")
        print(f"      - Strategies Tried: {result.strategies_tried}")
        
        if args.verbose:
            print()
            print(director.explain_intelligence())
        
        sys.exit(1)


if __name__ == "__main__":
    main()