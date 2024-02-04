from string import punctuation
from enum import Enum
from requests import Response, get
from urllib.parse import urlparse
from typing import Optional
from pydantic import BaseModel
from functools import cached_property

vowels: str = "aeiou"
consonants: str = "bcdfghjklmnpqrstvwxyz"
punctuations: str = punctuation


class URLLabel(str, Enum):
    """URL Type labels for learning tasks"""
    benign = "benign"
    malware = "malware"
    defacement = "defacement"
    phishing = "phishing"


class URLItem(BaseModel):
    url: str
    label: Optional[URLLabel] = None


class GenericURL(URLItem):

    @cached_property
    def cp_req(self) -> Optional[Response]:
        _url, _parsed = self.url, urlparse(self.url)
        if not bool(_parsed.scheme) or _url.startswith("www"):
            _url = f"http://{_url}"

        try:
            headers = {'user-agent': 'Mozilla/5.0'}
            return get(_url, allow_redirects=True, headers=headers, timeout=2.5)
        except Exception as e:
            return None
        
    @cached_property
    def cp_headers(self) -> Optional[dict[str, str]]:
        if self.cp_req:
            return {k.lower():v for k,v in self.cp_req.headers.items()}
        return {}

    @cached_property
    def resolved(self) -> str:
        if self.cp_req:
            return self.cp_req.url
        return self.url

    @cached_property
    def resolved_url(self):
        return urlparse(self.resolved)

    @cached_property
    def cp_scheme(self) -> str:
        return self.resolved_url.scheme
    
    @cached_property
    def cp_host(self) -> str:
        if not self.resolved_url.netloc:
            return self.url.split("//")[-1].split("/")[0]
        return self.resolved_url.netloc
    
    @cached_property
    def cp_domains(self) -> list[str]:
        domains = self.url.split("//")[-1].split("/")[0].split(".")
        domains = [d for d in domains if not d.startswith("www")]
        return domains
    
    @cached_property
    def cp_path(self) -> str:
        if not self.resolved_url.path:
            return self.url.split("//")[-1].split("/", 1)[-1]
        return self.resolved_url.path
    
    @cached_property
    def cp_query(self) -> Optional[str]:
        return self.resolved_url.query

    @cached_property
    def cp_query_params(self) -> list[Optional[tuple[str, str]]]:
        params = [
            tuple(qp.split("=")) for qp in 
                self.cp_query.split("&") if qp != ""
        ]
        return params
    
    @cached_property
    def cp_fragment(self) -> str:
        return self.resolved_url.fragment
    
    @cached_property
    def cp_port(self) -> str:
        return self.resolved_url.port
    
    @cached_property
    def cp_username(self) -> Optional[str]:
        return self.resolved_url.username
    
    @cached_property
    def cp_password(self) -> Optional[str]:
        return self.resolved_url.password
    

class FeatureSet(GenericURL):
    def __init__(self, url:str, label:Optional[URLLabel]=None) -> None:
        super().__init__(url=url, label=label)