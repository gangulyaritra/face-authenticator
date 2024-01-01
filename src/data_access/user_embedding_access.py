from src.database import MongoDBClient
from src.constant import EMBEDDING_COLLECTION_NAME


class UserEmbeddingAccess:
    def __init__(self) -> None:
        self.client = MongoDBClient()
        self.collection = self.client.database[EMBEDDING_COLLECTION_NAME]

    def save_user_embedding(self, uuid_: str, embedding_list) -> None:
        self.collection.insert_one({"UUID": uuid_, "user_embedding": embedding_list})

    def get_user_embedding(self, uuid_: str) -> dict:
        user: dict = self.collection.find_one({"UUID": uuid_})
        return user if user != None else None

    def delete_user_embedding(self, uuid_: str) -> None:
        return self.collection.delete_one({"UUID": uuid_})
