import logging
from requests import get
from json import loads
from functools import reduce, cached_property
from typing import Any, Generator, TypeVar

from pydantic_settings import BaseSettings

from lib.features.base import Feature, URLComponent
from lib.features.lexical import LexicalFeatures 
from lib.features.header import HeaderFeatures

from lib.data.db import Atlas

FI = TypeVar("FI", bound=Feature)

class FeatureExtractor(BaseSettings):
    aws_source: str
    mongo_extract_database: str
    mongo_extract_collection: str
    feature_sets: list[Any] = [LexicalFeatures, HeaderFeatures]

    @cached_property
    def atlas(self):
        return Atlas(
            mongo_database=self.mongo_extract_database,
            mongo_collection=self.mongo_extract_collection
        )
    

    @cached_property
    def feature_keys(self) -> list[str]:
        """Get Feature Keys from Features."""
        return reduce(
            lambda a, b: a + b, list(
                map(
                    lambda feature: feature.model_computed_fields.keys(), self.feature_sets
                )
            )
        )
    
    
    @staticmethod
    def extract_features(feature_sets:list[FI]) -> dict[str, Any]:
        """Get Features from Feature Instances."""
        return reduce(
            lambda a, b: dict(a, **b), list(
                map(
                    lambda feature_set: dict(
                        map(
                            lambda feature: (feature, getattr(feature_set, feature)),
                            feature_set.model_computed_fields.keys()
                        )
                    ), feature_sets
                )
            )
        )


    def load_data(self) -> Generator[dict, None, None]:
        """Load Data from Source."""
        lines = get(self.aws_source).text.split("\n")
        for line in lines:
            yield loads(line)

    def load_feature_sets(self) -> Generator[list, None, None]:
        """Load Feature Set Instances from Feature Set Objects."""
        for obj in self.load_data():
            if self.atlas.collection.find_one({"lx_url_raw": obj.get("url")}):
                print(f"URL {obj.get('url')} already exists in database.")
                continue

            yield list(
                map(
                    lambda feature: feature(components=URLComponent(**obj)), self.feature_sets
                )
            )

    def load_features(self) -> Generator[dict, None, None]:
        """Get Features from Feature Instances."""
        for feature_instance in self.load_feature_sets():
            yield self.extract_features(feature_instance)


    async def save(self) -> None:
        """Save Features to Database."""
        for feature in self.load_features():
            self.atlas.collection.insert_one(feature)
