
from json import loads
from requests import get
from typing import Generator

from lib.lexical import LexicalFeatures 


class DataLoader:
    """Data Loader for Loading Data from Source."""
    def __init__(self, source:str, data_dir:str, labels_file:str) -> None:
        self.source = source
        self.data_dir = data_dir 
        self.labels_file = labels_file
    
    @property
    def feature_keys(self):
        return LexicalFeatures.model_computed_fields.keys()
    
    def _extract_features(self, lexical:LexicalFeatures) -> dict:
        """Extract Lexical Features from Data."""
        features = {feature: getattr(lexical, feature) 
                        for feature in self.feature_keys}
        return features
    
    def write_headers(self) -> None:
        """Write Headers to File."""
        with open(self.labels_file, "w") as f:
            for _key in self.feature_keys:
                f.write(_key + "\n")

    def load_data(self) -> Generator[LexicalFeatures, None, None]:
        """Load Data from Source."""
        lines = get(self.source).text.split("\n")
        for line in lines:
            obj:dict = loads(line)
            obj = LexicalFeatures(url=obj.get("url", None), label=obj.get('label'))
            yield obj


    def load_features(self) -> Generator[dict, None, None]:
        """Load Lexical Features from Source."""
        for lexical in self.load_data():
            yield self._extract_features(lexical)
