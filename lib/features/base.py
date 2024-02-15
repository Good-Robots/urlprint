from math import log
from requests import Response, get
from urllib.parse import urlparse

from functools import cached_property
from collections import Counter

from enum import Enum
from typing import Any, Optional, TypeVar
from pydantic import BaseModel
from pydantic_settings import BaseSettings




class FeatureSet(BaseSettings):
    """Base Feature Set."""

    @cached_property
    def computed_fields(self) -> dict[str, Any]:
        return self.model_computed_fields
    
FI = TypeVar("FI", bound=FeatureSet)


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
    def make_request(url:str, allow_redirects:bool=True, timeout:int=3) -> Optional[Response]:
        """Make a request to a URL."""
        headers={'user-agent': 'Mozilla/5.0'}
        try:
            return get(url, allow_redirects=allow_redirects, headers=headers, timeout=timeout)
        except:
            return None

    @staticmethod
    def entropy(s: str) -> float:
        """Calculate the Shannon Entropy of a string."""
        p, lns = Counter(s), float(len(s))
        return -sum( count/lns * log(count/lns, 2) for count in p.values())
    
    @cached_property
    def cp_parsed_url(self):
        return urlparse(self.url)
    
    @cached_property
    def cp_response(self) -> Optional[Response]:
        if not bool(self.cp_parsed_url.scheme) or self.url.startswith("www"):
            return self.make_request(url=f"http://{self.url}")
        return self.make_request(url=self.url)
    
    @cached_property
    def cp_redirects(self) -> list[Response]:
        if bool(self.cp_response):
            return self.cp_response.history
        return []
    
    @cached_property
    def cp_resolved_to_host(self) -> bool:
        if not bool(self.cp_response):
            return False
        host1 = self.url.split("//")[-1].split("/")[0].strip("www")
        return host1 in self.cp_response.url
    
    @cached_property
    def cp_resolved(self) -> str:
        if not bool(self.cp_response):
            return self.url
        
        if self.cp_resolved_to_host and bool(self.cp_redirects):
            return self.url 
        return self.cp_response.url


    @cached_property
    def cp_parsed_resolved(self):
        return urlparse(self.cp_resolved)
    
    @cached_property
    def cp_headers(self) -> Optional[dict[str, str]]:
        if self.cp_response:
            return {k.lower():v for k,v in self.cp_response.headers.items()}
        return {}
    
    @cached_property
    def cp_status_code(self) -> Optional[int]:
        if self.cp_response:
            return self.cp_response.status_code
        return None

    @cached_property
    def cp_scheme(self) -> str:
        return self.cp_parsed_resolved.scheme
    
    @cached_property
    def cp_host(self) -> str:
        if not self.cp_parsed_resolved.netloc:
            return self.url.split("//")[-1].split("/")[0]
        return self.cp_parsed_resolved.netloc
    
    @cached_property
    def cp_domains(self) -> list[str]:
        domains = self.url.split("//")[-1].split("/")[0].split(".")
        domains = [d for d in domains if not d.startswith("www")]
        return domains
    
    @cached_property
    def cp_path(self) -> str:
        if not self.cp_parsed_resolved.path:
            return self.url.split("//")[-1].split("/", 1)[-1]
        return self.cp_parsed_resolved.path
    
    @cached_property
    def cp_query(self) -> Optional[str]:
        return self.cp_parsed_resolved.query

    @cached_property
    def cp_query_params(self) -> list[Optional[tuple[str, str]]]:
        params = [
            tuple(qp.split("=")) for qp in 
                self.cp_query.split("&") if qp != ""
        ]
        return params
    
    @cached_property
    def cp_fragment(self) -> str:
        return self.cp_parsed_resolved.fragment
    
    @cached_property
    def cp_port(self) -> Optional[int]:
        return self.cp_parsed_resolved.port
    
    @cached_property
    def cp_username(self) -> Optional[str]:
        return self.cp_parsed_resolved.username
    
    @cached_property
    def cp_password(self) -> Optional[str]:
        return self.cp_parsed_resolved.password

    
UC = TypeVar("UC", bound=URLComponent)