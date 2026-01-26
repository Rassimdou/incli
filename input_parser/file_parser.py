"""
Reads files containing URL targets and converts them into parsedURL objects 
this module is responsible ONLY for bulk input handling
"""


from typing import List
from input_parser.url_parser import URLParser, ParsedURL
from dataclasses import dataclass, field


@dataclass
class FileParser:
    """
    Parsers files containing URLs (one per line) into ParsedURL objects
    """

    def parse_file(self, file_path: str) -> List[ParsedURL]:
        parsed_urls = []
        seen = set()

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_number , line in enumerate(f, start=1):
                url = line.strip()

                #skip empty lines and comments 
                if not url or url.startswith('#'):
                    continue 
              
                # Deduplicate raw input 
                if url in seen:
                    continue
                seen.add(url)

                try:
                    parsed = self.url_parser.parse(url)
                    parsed_urls.append(parsed)
                except Exception as e:
                    # Malformed URLs are ignored silently
                    continue

        return parsed_urls