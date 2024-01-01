from src.database import MongoDBClient
from src.entity.user import UserDetail
from src.constant import USER_COLLECTION_NAME


class UserDataAccess:
    def __init__(self) -> None:
        self.client = MongoDBClient()
        self.collection = self.client.database[USER_COLLECTION_NAME]

    def save_user(self, user: UserDetail) -> None:
        self.collection.insert_one(user)

    def get_user(self, query: dict) -> dict:
        return self.collection.find_one(query)

    def update_user(self, filter: dict, query: dict) -> None:
        return self.collection.update_one(filter, {"$set": query})

    def delete_user(self, query: dict) -> None:
        return self.collection.delete_one(query)
