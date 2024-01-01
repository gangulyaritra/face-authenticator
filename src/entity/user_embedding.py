class UserEmbedding:
    def __init__(self, UUID: str = None, user_embedding=None) -> None:
        self.UUID = UUID
        self.user_embedding = user_embedding

    def to_dict(self) -> dict:
        return self.__dict__

    def __str__(self) -> str:
        return str(self.to_dict())
