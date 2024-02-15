from pydantic_settings import BaseSettings
from pymongo import MongoClient

class Mongo(BaseSettings):
    """MongoDB Database."""
    mongodb: str
    mongodb_uri: str
    collection: str

    @property
    def client(self) -> MongoClient:
        return MongoClient(self.mongodb_uri)

    @property
    def database(self):
        return self.client[self.mongodb]

    @property
    def col(self):
        return self.database[self.collection]

    def insert(self, data: dict) -> None:
        _exist = self.col.find_one(data)
        print(_exist)
        if not _exist:
            try:
                self.col.insert_one(data)
            except Exception as e:
                print(e)

    def find(self, query: dict) -> list[dict]:
        return list(self.col.find(query))

    def delete(self, query: dict) -> None:
        self.col.delete_many(query)

    def update(self, query: dict, data: dict) -> None:
        self.col.update_many(query, {"$set": data})