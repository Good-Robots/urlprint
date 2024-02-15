from json import loads
from typing import Any, Generator

from pydantic_settings import BaseSettings

from lib.features.host import HostFeatures
from lib.features.lexical import LexicalFeatures 
from lib.features.content import ContentFeatures
from lib.features.base import get, cached_property, URLComponent, FI

from utils.db import Mongo

feature_sets = [LexicalFeatures, ContentFeatures, HostFeatures]


class DataLoader(BaseSettings):
    """Data Loader Flow."""
    data_source: str 
    feature_sets: list[Any] = feature_sets
    client: Mongo = Mongo()

    @staticmethod
    def _flatten(items:list[dict|list]) -> Any:
        """Compress Dictionary."""
        if isinstance(items[0], dict):
            return {k: v for d in items for k, v in d.items()}
        return [sublist for list in items for sublist in list]
    
    
    @staticmethod
    def extract_features(feature_sets:list[FI]) -> list[dict]:
        """Get Features from Feature Instances."""
        features = list(
                map(
                    lambda feature_set: 
                        dict(
                            map(
                                lambda key: (key, getattr(feature_set, key)),
                                feature_set.model_computed_fields.keys()
                            ),
                        ),
                        feature_sets
                )
            )
        return features


    @cached_property
    def feature_keys(self) ->dict|list:
        """Get Feature Keys from Features."""
        _keys = [
            feature.model_computed_fields.keys()
                    for feature in self.feature_sets]
        return self._flatten(_keys)


    def load_data(self) -> Generator[dict, None, None]:
        """Load Data from Source."""
        lines = get(self.data_source).text.split("\n")
        for line in lines:
            yield loads(line)


    def load_feature_sets(self) -> Generator[list[FI], None, None]:
        """Load Feature Set Instances from Feature Set Objects."""
        for obj in self.load_data():
            indb = self.client.find({"lx_url_raw": obj.get("url")})

            if not bool(indb): 
                components = URLComponent(**obj)
                _feature_instances = [
                    feature_set(components=components) 
                            for feature_set in self.feature_sets]
                yield _feature_instances
            else:
                print(f"Seen {obj.get('url')} before. Skipping")
            

    def load_features(self) -> Generator[dict, None, None]:
        """Get Features from Feature Instances."""
        for feature_instance in self.load_feature_sets():
            yield self._flatten(self.extract_features(feature_instance))


    async def save(self) -> None:
        """Save Features to Database."""
        for feature in self.load_features():
            self.client.insert(feature)
