from functools import cached_property
from pydantic_settings import BaseSettings
from pymongo import MongoClient


class Atlas(BaseSettings):
    """Atlas Database."""
    mongo_uri: str = "mongodb://root:password@localhost:27017/?authSource=admin"
    mongo_database: str
    mongo_collection: str

    @cached_property
    def uri(self) -> str:
        return self.mongo_uri
    
    @property
    def client(self) -> MongoClient:
        return MongoClient(self.uri)

    @property
    def database(self):
        return self.client[self.mongo_database]

    @property
    def collection(self):
        return self.database[self.mongo_collection]
    