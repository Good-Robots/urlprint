import logging
import socket
from datetime import date, datetime, timezone
from time import sleep

from typing import Any, Generator, Optional
from pydantic import computed_field

from shodan import Shodan
from wayback import CdxRecord, WaybackClient

from lib.features.base import get, cached_property, UC, FeatureSet




class HostRequest(FeatureSet):
    model_config = {"arbitrary_types_allowed": True}
    components: UC
    shodan_key: str

    @cached_property
    def shodan(self) -> Shodan:
        return Shodan(self.shodan_key)
    
    @cached_property
    def client(self) -> WaybackClient:
        return WaybackClient()

    @cached_property
    def today(self) -> date:
        return datetime.now(timezone.utc).date()

    @cached_property
    def ip_address(self) -> str:
        try:
            return socket.gethostbyname(self.components.cp_host)
        except:
            return ""
    
    @cached_property
    def shodan_info(self) -> dict:
        try:
            endpoint = f"https://api.shodan.io/shodan/host/{self.ip_address}?key={self.shodan_key}"
            return get(endpoint, timeout=1).json()
        except Exception as e:
            sleep(5)
            return {}
    
    @cached_property
    def host_domains(self) -> list[str]:
        try:
            return self.shodan_info.get('domains', [])
        except Exception as e:
            logging.error(e)
            return []
    
    @cached_property
    def ports(self) -> list[int]:
        try:
            return self.shodan_info.get('ports', [])
        except Exception as e:
            logging.error(e)
            return []
    
    @cached_property
    def vulnerabilities(self) -> list[str]:
        try:
            return self.shodan_info.get('vulns', [])
        except Exception as e:
            logging.error(e)
            return []
    
    @cached_property
    def shodan_services(self) -> list[dict]:
        try:
            return self.shodan_info.get('data', [{}])
        except Exception as e:
            logging.error(e)
            return [{}]
    
    @cached_property
    def ssl_data(self) -> dict:
        ssl_info = list(
            filter(
                lambda x: x.get('port', None) == 443,
                self.shodan_services
            )
        )
        if bool(ssl_info):
            return ssl_info[-1].get('ssl', {})
        return {}
    
    @cached_property
    def search(self) -> Generator[CdxRecord, Any, None]:
        try:
            return self.client.search(
                self.components.cp_resolved.split("?")[0], 
                matchType="exact", skip_malformed_results=True
            )
        except Exception as e:
            logging.error(e)
            return []
    
    @cached_property
    def updates(self) -> list[CdxRecord]:
        try:
            return list(self.search)
        except Exception as e:
            logging.error(e)
            return []
    
    @cached_property
    def has_updates(self) -> Optional[bool]:
        try:
            return len(self.updates) > 0
        except Exception as e:
            logging.error(e)
            return None
    
    @cached_property
    def total_updates(self) -> Optional[int]:
        try:
            return len(self.updates)
        except Exception as e:
            logging.error(e)
            return None
    
    @cached_property
    def timestamps(self) -> list[datetime]:
        try:
            return [update_.timestamp for update_ in self.updates]
        except Exception as e:
            logging.error(e)
            return []
    
    @cached_property
    def last_update(self) -> Optional[datetime]:
        if bool(self.timestamps):
            return self.timestamps[-1]
        return None
    
    @cached_property
    def first_update(self) -> Optional[datetime]:
        if bool(self.timestamps):
            return self.timestamps[0]
        return None
    
    @cached_property
    def live_updates(self) -> list[CdxRecord]:
        lives = list(
            filter(
                lambda x: x.status_code == 200,
                self.updates
            )
        )
        return lives
    
    @cached_property
    def ct_cert(self) -> dict:
        return self.ssl_data.get('cert', None)



class HostFeatures(HostRequest):
    @computed_field
    @cached_property
    def ht_open_port_443(self) -> Optional[bool]:
        try:
            return 443 in self.ports
        except Exception as e:
            logging.error(e)
            return None

    @computed_field
    @cached_property
    def ht_has_cert(self) -> bool:
        if bool(self.ct_cert):
            return True
        return False
        
    @computed_field
    @cached_property
    def ht_url_age(self) -> Optional[int]:
        try:
            udate = self.first_update.date()
            return (self.today - udate).days
        except Exception as e:
            logging.error(e)
            return None
    
    @computed_field
    @cached_property
    def ht_days_since_last_update(self) -> Optional[int]:
        try:
            udate = self.last_update.date()
            return (self.today - udate).days
        except Exception as e:
            logging.error(e)
            return None
    
    @computed_field 
    @cached_property
    def ht_update_frequency(self) -> Optional[float]:
        try:
            return self.ht_url_age / self.total_updates
        except Exception as e:
            return None
    
    @computed_field
    @cached_property
    def ht_ssl_version(self) -> Optional[str]:
        if bool(self.ct_cert):
            return self.ct_cert.get('version', None)
        return None
    
    
    @computed_field
    @cached_property
    def ht_is_ipv6(self) -> Optional[bool]:
        return ':' in self.ip_address

    
    @computed_field
    @cached_property
    def ht_is_ipv4(self) -> Optional[bool]:
        return '.' in self.ip_address

    
    @computed_field
    @cached_property
    def ht_region(self) -> str:
        x = self.shodan_info.get('region_code', ",")
        if bool(x):
            return x.replace(",", "")
        return ""

    
    @computed_field
    @cached_property
    def ht_country(self) -> str:
        x = self.shodan_info.get('country_name', ",")
        if bool(x):
            return x.replace(",", "")
        return ""

    
    @computed_field
    @cached_property
    def ht_city(self) -> Optional[str]:
        x = self.shodan_info.get('city', ",")
        if bool(x):
            return x.replace(",", "")
        return ""
    
    @computed_field
    @cached_property
    def ht_area_code(self) -> Optional[str]:
        x = self.shodan_info.get('area_code', ",") 
        if bool(x):
            return x.replace(",", "")
        return ""

    
    @computed_field
    @cached_property
    def ht_org(self) -> Optional[str]:
        x = self.shodan_info.get('org', ",")
        if bool(x):
            return x.replace(",", "")
        return ""
        
    
    @computed_field
    @cached_property
    def ht_isp(self) -> Optional[str]:
        x = self.shodan_info.get('isp', ",")
        if bool(x):
            return x.replace(",", "")
        return ""
        
    
    @computed_field
    @cached_property
    def ht_asn(self) -> Optional[str]:
        x = self.shodan_info.get('asn', ",")
        if bool(x):
            return x.replace(",", "")
        return ""
        
    
    @computed_field
    @cached_property
    def ht_total_open_ports(self) -> Optional[int]:
        if bool(self.ports):
            return len(self.ports)
        return None
        
    
    @computed_field
    @cached_property
    def ht_total_vulnerabilities(self) -> Optional[int]:
        if bool(self.vulnerabilities):
            return len(self.vulnerabilities)
        return None
    
    @computed_field
    @cached_property
    def ht_total_services(self) -> Optional[int]:
        if bool(self.shodan_services):
            return len(self.shodan_services)
        return None
    
    @computed_field
    @cached_property
    def ht_certificate_issued(self) -> Optional[datetime]:
        if bool(self.ct_cert):
            ts = self.ct_cert.get('issued', None)
            return datetime.strptime(ts, "%Y%m%d%H%M%SZ")
        return None
    
    @computed_field
    @cached_property
    def ht_certificate_expiry(self) -> Optional[datetime]:
        if bool(self.ct_cert):
            ts = self.ct_cert.get('expires', None)
            return datetime.strptime(ts, "%Y%m%d%H%M%SZ")
        return None
        
    @computed_field
    @cached_property
    def ht_days_to_expiry(self) -> Optional[int]:
        try:
            return (self.ht_certificate_expiry.date() - self.today).days
        except Exception as e:
            logging.error(e)
            return None
        
    @computed_field
    @cached_property
    def ht_certificate_age(self) -> Optional[int]:
        try:
            return (self.today - self.ht_certificate_issued.date()).days
        except Exception as e:
            logging.error(e)
            return None
    