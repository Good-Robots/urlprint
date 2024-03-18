import ssl
import logging
from functools import cached_property
from typing import Optional
from datetime import date, datetime

from pydantic import computed_field

from cryptography import x509
from cryptography.x509 import Certificate

from lib.features.base import Feature, URLComponent


class HeaderFeatures(Feature):
    components: URLComponent
    
    @staticmethod
    def _get_header_key(prop:str|None, _key:str, delim:str=",") -> Optional[int]:
        if bool(prop):
            values = list(
                map(
                    lambda x: x.split("=")[-1], 
                    filter(
                        lambda x: _key in x, prop.split()
                    )
                )
            )
            if bool(values):
                try:
                    value = values[0].strip().split(delim)[0]
                    return int(value)
                except Exception as e:
                    logging.error(e)
                    return None
        return None
    
    @cached_property
    def certificate(self) -> str|None:
        if bool(self.components.cp_scheme) and bool(self.components.cp_host):
            if "https" in self.components.cp_scheme.lower():
                try:
                    return ssl.get_server_certificate((self.components.cp_host, 443), timeout=5)
                except Exception as e:
                    logging.error(e)
        return None
    
    @cached_property
    def hd_response(self):
        return self.components.cp_response
    
    @cached_property
    def hd_has_headers(self) -> Optional[bool]:
        try:
            return bool(self.hd_response.headers)
        except Exception as e:
            logging.error(e)
            return None
    
    @cached_property
    def hd_certificate(self) -> Certificate|None:
        if self.certificate:
            try:
                return x509.load_pem_x509_certificate(
                    str.encode(
                        self.certificate
                    )
                )
            except Exception as e:
                logging.error(e)
        return None
    
    @cached_property
    def _hd_certificate_issued(self) -> Optional[date]:
        if bool(self.hd_certificate):
            return self.hd_certificate.not_valid_before_utc.date()

    @cached_property
    def _hd_certificate_expires(self) -> Optional[date]:
        if bool(self.hd_certificate):
            return self.hd_certificate.not_valid_after_utc.date()
    
    @computed_field
    @cached_property
    def hd_status_code(self) -> Optional[int]:
        try:
            return self.hd_response.status_code
        except Exception as e:
            logging.error(e)
            return None

    
    @computed_field
    @cached_property
    def hd_response_time(self) -> Optional[float]:
        try:
            return self.hd_response.elapsed.total_seconds()
        except Exception as e:
            logging.error(e)
            return None

    
    @computed_field
    @cached_property
    def hd_encoding(self) -> Optional[str]:
        try:
            return self.hd_response.encoding
        except Exception as e:
            logging.error(e)
            return None
        
    @computed_field
    @cached_property
    def hd_content_encoding(self) -> Optional[str]:
        try:
            return self.hd_response.headers.get("content-encoding", None)
        except Exception as e:
            logging.error(e)
            return None
        
    @computed_field
    @cached_property
    def hd_last_modified(self) -> Optional[date]:
        
        try:
            date_str = self.hd_response.headers.get("last-modified", None)
            return self.parse_date_string(date_str)
        except Exception as e:
            logging.error(e)
            return None
        
    @computed_field
    @cached_property
    def hd_num_header_keys(self) -> Optional[int]:
        try:
            return len(self.hd_response.headers.keys())
        except Exception as e:
            logging.error(e)
            return None
        
    @computed_field
    @cached_property
    def hd_connection(self) -> Optional[str]:
        if bool(self.hd_response):
            if self.hd_response.headers:
                return self.hd_response.headers.get("connection", None)
    
    @computed_field
    @cached_property
    def hd_server(self) -> Optional[str]:
        if bool(self.hd_response):
            if self.hd_response.headers:
                return self.hd_response.headers.get("server", None)
    
    @computed_field
    @cached_property
    def hd_content_type(self) -> Optional[str]:
        if bool(self.hd_response):
            if self.hd_response.headers:
                return self.hd_response.headers.get("content-type", None)
    
    @computed_field
    @cached_property
    def hd_cache_control(self) -> Optional[str]:
        if bool(self.hd_response):
            if self.hd_response.headers:
                return self.hd_response.headers.get("cache-control", None)
    
    @computed_field
    @cached_property
    def hd_keep_alive(self) -> Optional[str]:
        if bool(self.hd_response):
            if self.hd_response.headers:
                return self.hd_response.headers.get("keep-alive", None)
    
    @computed_field
    @cached_property
    def hd_keep_alive_timeout(self) -> Optional[int]:
        try:
            return self._get_header_key(self.hd_keep_alive, "timeout")
        except Exception as e:
            logging.error(e)
            return None

    @computed_field
    @cached_property
    def hd_keep_alive_max(self) -> Optional[int]:
        try:
            return self._get_header_key(self.hd_keep_alive, "max")
        except Exception as e:
            logging.error(e)
            return None
    
    @computed_field
    @cached_property
    def hd_cache_max_age(self) -> Optional[int]:
        try:
            return self._get_header_key(self.hd_cache_control, "max-age")
        except Exception as e:
            logging.error(e)
            return None
    
    @computed_field
    @cached_property
    def hd_content_length(self) -> Optional[str]:
        try:
            return self.hd_response.headers.get("content-length", None)
        except Exception as e:
            logging.error(e)
            return None
    
    @computed_field
    @cached_property
    def hd_xss_protection(self) -> Optional[str]:
        if bool(self.hd_response):
            if self.hd_response.headers:
                return self.hd_response.headers.get("x-xss-protection", None)

    @computed_field
    @cached_property
    def hd_x_content_type_options(self) -> Optional[str]:
        if bool(self.hd_response):
            if self.hd_response.headers:
                return self.hd_response.headers.get("x-content-type-options", None)
    
    @computed_field
    @cached_property
    def hd_x_last_modified(self) -> Optional[date]:
        if bool(self.hd_response):
            if self.hd_response.headers:
                return self.parse_date_string(self.hd_response.headers.get("last-modified", None))
    @computed_field
    @cached_property
    def hd_expires(self) -> Optional[date]:
        try:
            return self.parse_date_string(self.hd_response.headers.get("expires", None))
        except Exception as e:
            logging.error(e)
        return None

    
    @computed_field
    @cached_property
    def hd_num_header_params(self) -> Optional[int]:
        if bool(self.hd_response):
            if self.hd_response.headers:
                return len(self.hd_response.headers)
            
    @computed_field
    @cached_property
    def hd_header_entropy(self) -> Optional[float]:
        if bool(self.hd_response):
            if self.hd_response.headers:
                return self.entropy("".join(self.hd_response.headers.values()))
    
    @computed_field
    @cached_property
    def hd_num_redirects(self) -> Optional[int]:
        if bool(self.hd_response):
            if self.hd_response.history:
                return len(self.hd_response.history) -1
    
    @computed_field
    @cached_property
    def hd_cookie_entropy(self) -> Optional[float]:
        try:
            return self.entropy("".join(self.hd_response.cookies.values()))
        except Exception as e:
            logging.error(e)
        return None
    
    @computed_field
    @cached_property
    def hd_num_cookie_params(self) -> Optional[int]:
        if bool(self.hd_response):
            if self.hd_response.cookies:
                return len(self.hd_response.cookies)


    @computed_field
    @cached_property
    def hd_certificate_issued(self) -> Optional[str]:
        if bool(self._hd_certificate_issued):
            return self._hd_certificate_issued.isoformat()

    @computed_field
    @cached_property
    def hd_certificate_expires(self) -> Optional[str]:
        if bool(self._hd_certificate_expires):
            return self._hd_certificate_expires.isoformat()
        
    @computed_field
    @cached_property
    def hd_cerificate_duration(self) -> Optional[float]:
        if bool(self._hd_certificate_issued) and bool(self._hd_certificate_expires):
            return (self._hd_certificate_expires - self._hd_certificate_issued).days
        
    @computed_field
    @cached_property
    def hd_certificate_age(self) -> Optional[float]:
        if bool(self._hd_certificate_issued):
            return (self._hd_certificate_issued - datetime.now().date()).days
        
    @computed_field
    @cached_property
    def hd_certificate_days_left(self) -> Optional[float]:
        if bool(self._hd_certificate_expires):
            return (self._hd_certificate_expires - datetime.now().date()).days
        
    @computed_field
    @cached_property
    def hd_certificate_expired(self) -> Optional[bool]:
        if bool(self.hd_certificate_days_left):
            return self.hd_certificate_days_left < 0
        

    @computed_field
    @cached_property
    def hd_certificate_entropy(self) -> Optional[float]:
        if bool(self.hd_certificate):
            return self.entropy(self.certificate)

        
    @computed_field
    @cached_property
    def hd_certificate_num_extensions(self) -> int:
        if bool(self.hd_certificate):
            if bool(self.hd_certificate.extensions):
                return len(self.hd_certificate.extensions)
        return 0

