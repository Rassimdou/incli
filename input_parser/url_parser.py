from urllib.parse import urlparse, parse_qsl, unquote
from dataclasses import dataclass, field
from typing import List, Dict , Optional 


#DATA models 

@dataclass 
class QueryParameter:
    name: str 
    raw_value: Optional[str]
    decoded_value: Optional[str]
    is_empty: bool
    is_path_like: bool


@dataclass
class ParsedURL:
    original_input: str 
    scheme: str 
    host: str
    port: Optional[int]
    path: str 
    base_url: str
    query_params: List[QueryParameter] = field(default_factory=list)
    path_segments: List[str] = field(default_factory=list)




#URL Parser 


class URLParser:
    """
    Responsible for parsing and normalizing a single URL into
    a structured , injectable representation
    """

    DEFAULT_SCHEME = "http"
    

    def parse(self, url: str) -> ParsedURL:
        original_input = url_input.strip()
        
        narmalized_url = self._nrmalize_url(original_input)
        parsed = urlparse(normalized_url)

        scheme = parsed.scheme
        host = parsed.hostname 
        port = parsed.port
        path = parsed.path or "/"

        base_url = self._build_base_url(scheme, host, port)

        query_params = self._parse_query_params(parsed.query)
        path_segmetns = self._parse_path_segments(path)

        return ParsedURL(
            original_input=original_input,
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            base_url=base_url,
            query_params=query_params,
            path_segments=path_segments,
        )
    

    #INRERNA HELPERS

    def _normalize_url(self, url: str) -> str:
        """
        ENsure the URL has a scheme and its perseable.
        Doesnt decode or mutate parameters.
        """

        if "://" not in url_input:
            return f"{self.DEFAULT_SCHEME}://{url_input}"
        return url_input
    
    def _build_base_url(self, scheme:str , host:str , port: Optional[int]):
        if not port:
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"
    
    def _parse_query_params(self, query:str) -> List[QueryParameter]:
        params = []
        for name, raw_value in parse_qsl(query, keep_blank_values=True):
            decoded_value = unquote(raw_value) if raw_value is not None else None
            is_empty = raw_value == ""  or raw_value is None
            is_path_like = self._is_path_like(name, decoded_value)

            param = QueryParameter(
                name=name,
                raw_value=raw_value,
                decoded_value=decoded_value,
                is_empty=is_empty,
                is_path_like=is_path_like,
            )
            params.append(param)
        return params
    

    def _parse_path_segments(self, path: str ) -> List[str]:
        """
        Splits the path into segments for path-based injection
        """
        segments = [seg for seg in path.split("/") if seg]
        return segments 
    

    def _is_path_like(self, name:str , value: Optional[str]) ->bool :
        """
        Heuristic to detect file/path-like parameters
        """

        indicators = ("file", "path", "dir", "include", "view", "template")

        if any(k in name.lower() for k in indicators):
            return True 
        
        if value:
            if "/" in value or "\\" in value or "." in value:
                return True
            

        return False