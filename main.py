from json import loads
from requests import get
from typing import Generator

from lib.base import GenericURL
from lib.lexical import LexicalFeatures 


source = "https://ennys.s3.eu-north-1.amazonaws.com/urls.json"


class DataLoader:
    """Data Loader for Loading Data from Source."""
    def __init__(self, source:str=source) -> None:
        self.source = source

    @staticmethod
    def _get_features(data:GenericURL) -> dict:
        """Extract Lexical Features from Data."""
        url, label = data.url, data.label
        return LexicalFeatures(url=url, label=label)
    
    @staticmethod
    def _extract_features(lexical:dict) -> dict:
        """Extract Lexical Features from Data."""
        features = {feature: getattr(lexical, feature) 
                        for feature in lexical.__class__.__dict__
                            if any(feature.startswith(prefix) 
                                    for prefix in ["lx_", "cp_"]
                                )}
        return features

    def load_data(self) -> Generator[GenericURL, None, None]:
        """Load Data from Source."""
        lines = get(self.source).text.split("\n")
        for line in lines:
            obj:dict = loads(line)
            obj = {
                    "url": obj.get("url", None), 
                    "label": obj.get('label')
                }
            yield GenericURL(**obj)


    def load_features(self) -> Generator[dict, None, None]:
        """Load Lexical Features from Source."""
        for data in self.load_data():
            lexical = self._get_features(data)
            yield self._extract_features(lexical)
