from pydantic import Field
from functools import cached_property
from typing import Annotated
from pydantic_settings import BaseSettings

from random import sample
from torch.utils.data import Dataset

from lib.data.db import Atlas

TrainSize = Annotated[float, Field(default=0.8, ge=1, le=0)]

class URI(BaseSettings):
    """MongoDB URI."""
    mongo_load_database:str
    mongo_load_collection:str
    mongo_train_collection:str
    mongo_test_collection:str

    @cached_property
    def atlas(self):
        return Atlas(mongo_database=self.mongo_load_database, mongo_collection=self.mongo_load_collection)


class URLDataset(Dataset):
    def __init__(self, train_size:TrainSize=0.8, uri=URI()):
        self.train_size = train_size
        self.uri = uri

    @cached_property
    def __all__(self):
        return list(self.uri.atlas.collection.find({}, {"raw": 0}))
    
    @cached_property
    def __ids__(self):
        return list(self.uri.atlas.collection.find({}, {"_id": 1}))

    @cached_property
    def __len__(self):
        return self.uri.atlas.collection.count_documents({})
    
    def __sample__(self):
        return self.uri.atlas.collection.aggregate([{"$sample": {"size": 1}}])
    
    def __getitem__(self, idx):
        return self.__all__[idx]
    
    def __download__(self):
        train = sample(self.__all__, round(self.__len__ * self.train_size))
        test = self.uri.atlas.database['urls'].find({"_id": {"$nin": [i["_id"] for i in train]}})
        return train, list(test)
    
    def __todb__(self, train:list[dict], test:list[dict]):
        database = self.uri.atlas.database
        database.drop_collection(self.uri.mongo_train_collection)
        database.drop_collection(self.uri.mongo_test_collection)
        database.create_collection(self.uri.mongo_train_collection)
        database.create_collection(self.uri.mongo_test_collection)
        database['train'].insert_many(train)
        database['test'].insert_many(test)
        return 

    
    def load(self):
        train, test = self.__download__()
        self.__todb__(train, test)