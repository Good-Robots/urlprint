from enum import Enum
from requests import head
from urllib.parse import urlparse
from typing import Optional
from pydantic import BaseModel, computed_field
from functools import cached_property


class URLLabel(str, Enum):
    """URL Type labels for learning tasks"""
    benign = "benign"
    malware = "malware"
    defacement = "defacement"
    phishing = "phishing"


class GenericURL(BaseModel):
    url: str
    label: Optional[URLLabel] = None


class URL(GenericURL):

    @cached_property
    def resolved(self):
        _url, _parsed = self.url, urlparse(self.url)
        if not bool(_parsed.scheme):
            _url = f"http://{_url}"

        try:
            req = head(_url, allow_redirects=True, timeout=1)
            return req.url
        except:
            return _url

    @cached_property
    def resolved_url(self):
        return urlparse(self.url)

    @computed_field
    @cached_property
    def cp_scheme(self) -> str:
        return self.resolved_url.scheme
    
    @computed_field
    @cached_property
    def cp_host(self) -> str:
        if not self.resolved_url.netloc:
            return self.url.split("//")[-1].split("/")[0]
        return self.resolved_url.netloc
    
    @computed_field
    @cached_property
    def cp_path(self) -> str:
        if not self.resolved_url.path:
            return self.url.split("//")[-1].split("/", 1)[-1]
        return self.resolved_url.path
    
    @computed_field
    @cached_property
    def cp_query(self) -> Optional[str]:
        return self.resolved_url.query
    
    @computed_field
    @cached_property
    def cp_query_params(self) -> list[Optional[tuple[str, str]]]:
        params = [
            tuple(qp.split("=")) for qp in 
                self.resolved_url.query.split("&") if qp != ""
        ]
        return params
    
    @computed_field
    @cached_property
    def cp_fragment(self) -> Optional[str]:
        return self.resolved_url.fragment
    
    @computed_field
    @cached_property
    def cp_port(self) -> Optional[str]:
        return self.resolved_url.port
    
    @computed_field
    @cached_property
    def cp_username(self) -> Optional[str]:
        return self.resolved_url.username
    
    @computed_field
    @cached_property
    def cp_password(self) -> Optional[str]:
        return self.resolved_url.password