import logging
from math import log
from collections import Counter
from functools import cached_property
from datetime import datetime, date, timezone
from dateutil.parser import parse
from pydantic import BaseModel
from requests import Response, head
from urllib.parse import urlparse

from functools import cached_property

from enum import Enum
from typing import Any, Optional

    
class URLLabel(str, Enum):
    """URL Type labels for learning tasks"""
    benign = "benign"
    malware = "malware"
    defacement = "defacement"
    phishing = "phishing"


class URLItem(BaseModel):
    url: str
    label: Optional[URLLabel] = None


class URLComponent(URLItem):
    @staticmethod
    def _get_host(url:str) -> str:
        return url.split("://")[-1].split("/")[0].strip("www.")

    @staticmethod
    def _make_head_request(url:str, timeout:int,  allow_redirects:bool=True) -> Optional[Response]:
        """Make a request to a URL."""
        headers={'user-agent': 'Mozilla/5.0'}
        try:
            req = head(url, allow_redirects=allow_redirects, headers=headers, timeout=timeout)
            logging.info(f"Request to {url} was successful with {req.status_code}.")
            return req
        except Exception as e:
            logging.error(f"Error making request to {url}: {e}")
            return None
        
    @cached_property
    def today(self) -> date:
        return datetime.now(timezone.utc).date()
    
    
    @cached_property
    def cp_response(self) -> Optional[Response]:
        _url = self.url
        if "://" not in self.url and not self.url.startswith("http"):
            _url = f"http://{self.url}"
        return self._make_head_request(_url, 3)
    
    @cached_property
    def cp_redirects(self) -> list[Response]:
        if bool(self.cp_response):
            return self.cp_response.history
        return []
    
    @cached_property
    def cp_resolved_to_host(self) -> Optional[bool]:
        if not bool(self.cp_response):
            return None
        return self._get_host(self.cp_response.url) == self._get_host(self.url)
    
    @cached_property
    def cp_resolved(self) -> str:

        if not bool(self.cp_response):
            return self.url
        
        if bool(self.cp_resolved_to_host) and len(self.cp_redirects) > 1:
            return self.url
        
        return self.cp_response.url

    @cached_property
    def cp_parsed_resolved(self):
        return urlparse(self.cp_resolved)
    
    @cached_property
    def cp_headers(self) -> Optional[dict[str, Any]]:
        print(self.cp_resolved)
        if bool(self.cp_response):
            return {k.lower():v for k,v in self.cp_response.headers.items()}
        return {}
    
    @cached_property
    def cp_status_code(self) -> Optional[int]:
        if bool(self.cp_response):
            return self.cp_response.status_code
        return None
    
    @cached_property
    def cp_cookies(self) -> Optional[dict[str, Any]]:
        if bool(self.cp_response):
            return self.cp_response.cookies.get_dict()
        return {}

    @cached_property
    def cp_scheme(self) -> str:
        return self.cp_parsed_resolved.scheme
    
    @cached_property
    def cp_host(self) -> str:
        if self.cp_parsed_resolved.netloc:
            return self.cp_parsed_resolved.netloc
        return self._get_host(self.cp_resolved)
    
    @cached_property
    def cp_path(self) -> str:
        if self.cp_parsed_resolved.path:
            return self.cp_parsed_resolved.path
        return self.url.split("//")[-1].split("/", 1)[-1]
        
    @cached_property
    def cp_query(self) -> Optional[str]:
        return self.cp_parsed_resolved.query

    @cached_property
    def cp_query_params(self) -> list[Optional[tuple[str, str]]]:
        if not bool(self.cp_query):
            return []
        
        params = [
            tuple(qp.split("=")) for qp in 
                self.cp_query.split("&") if qp != ""
        ]
        return params
    
    @cached_property
    def cp_fragments(self) -> list[str]:
        return self.cp_parsed_resolved.fragment.split("#")
    
    @cached_property
    def cp_port(self) -> Optional[int]:
        return self.cp_parsed_resolved.port
    
    @cached_property
    def cp_username(self) -> Optional[str]:
        return self.cp_parsed_resolved.username
    
    @cached_property
    def cp_password(self) -> Optional[str]:
        return self.cp_parsed_resolved.password


class Feature(BaseModel):
    """Base Feature Set Class."""
    class Config:
        arbitrary_types_allowed = True

    @staticmethod 
    def parse_date_string(date_str: str|None) -> date|None:
        """Parse a date string."""
        try:
            return parse(
                date_str, fuzzy=True, 
                default=
                datetime.now(timezone.utc)
            )
        except Exception as e:
            logging.error(f"Error parsing date string: {e}")
        return None
        

    @staticmethod
    def entropy(s: str) -> float:
        """Calculate the Shannon Entropy of a string."""
        p, lns = Counter(s), float(len(s))
        return -sum( count/lns * log(count/lns, 2) for count in p.values())

    @cached_property
    def computed_fields(self) -> dict[str, Any]:
        return self.model_computed_fields
