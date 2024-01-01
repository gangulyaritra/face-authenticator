import io
import sys
import numpy as np
from ast import Bytes
from typing import List
from deepface import DeepFace
from deepface.commons.functions import detect_face
from PIL import Image

from src.constant import *
from src.data_access.user_embedding_access import UserEmbeddingAccess
from src.exception import CustomException
from src.logger import logging


class UserLoginEmbeddingValidation:
    def __init__(self, uuid_: str) -> None:
        self.uuid_ = uuid_
        self.user_embedding_data = UserEmbeddingAccess()
        self.user = self.user_embedding_data.get_user_embedding(uuid_)

    def validate(self) -> bool:
        try:
            if self.user["UUID"] is None:
                return False
            return self.user["user_embedding"] is not None

        except Exception as e:
            raise e

    @staticmethod
    def generate_embedding(img_array: np.ndarray) -> np.ndarray:
        """
        Generate embedding from the image array.
        """
        try:
            faces = detect_face(
                img_array,
                detector_backend=DETECTOR_BACKEND,
                enforce_detection=ENFORCE_DETECTION,
            )
            return DeepFace.represent(
                img_path=faces[0],
                model_name=EMBEDDING_MODEL_NAME,
                enforce_detection=ENFORCE_DETECTION,
            )
        except Exception as e:
            raise CustomException(e, sys) from e

    @staticmethod
    def generate_embedding_list(files: List[Bytes]) -> List[np.ndarray]:
        """
        Generate an embedding list from the image array.
        """
        embedding_list = []

        for contents in files:
            img = Image.open(io.BytesIO(contents))
            img_array = np.array(img)
            embedding = UserLoginEmbeddingValidation.generate_embedding(img_array)
            embedding_list.append(embedding)

        return embedding_list

    @staticmethod
    def average_embedding(embedding_list: List[np.ndarray]) -> List:
        """
        Calculate the average embedding of the list of embeddings.
        """
        avg_embedding = np.mean(embedding_list, axis=0)
        return avg_embedding.tolist()

    @staticmethod
    def cosine_simmilarity(db_embedding, current_embedding) -> bool:
        """
        Calculate the cosine similarity between two embeddings.
        """
        try:
            return np.dot(db_embedding, current_embedding) / (
                np.linalg.norm(db_embedding) * np.linalg.norm(current_embedding)
            )
        except Exception as e:
            raise CustomException(e, sys) from e

    def compare_embedding(self, files: bytes) -> bool:
        """
        Compare the embedding of the current image with the embedding of the database.
        """
        try:
            if self.user:
                # Validate User Embedding.
                logging.info("Validating User Embedding ......")
                if self.validate() == False:
                    return False
                logging.info("Embedding Validation Successful.")

                # Generate Embedding List.
                logging.info("Generating Embedding List ......")
                embedding_list = UserLoginEmbeddingValidation.generate_embedding_list(
                    files
                )
                logging.info("Embedding List Generated Successfully.")

                # Calculate Average Embedding.
                logging.info("Calculating Average Embedding ......")
                avg_embedding_list = UserLoginEmbeddingValidation.average_embedding(
                    embedding_list
                )
                logging.info("Average Embedding Calculated Successfully.")

                # Fetch embedding from the database.
                db_embedding = self.user["user_embedding"]

                # Calculate Cosine Similarity.
                logging.info("Calculating Cosine Similarity ......")
                simmilarity = UserLoginEmbeddingValidation.cosine_simmilarity(
                    db_embedding, avg_embedding_list
                )
                logging.info("Cosine Similarity Calculated Successfully.")

                if simmilarity >= SIMILARITY_THRESHOLD:
                    logging.info("User Authenticated Successfully.")
                    return True
                else:
                    logging.info("User Authentication Failed.")
                    return False

            logging.info("User Authentication Failed.")
            return False

        except Exception as e:
            raise CustomException(e, sys) from e


class UserRegisterEmbeddingValidation:
    def __init__(self, uuid_: str) -> None:
        self.uuid_ = uuid_
        self.user_embedding_data = UserEmbeddingAccess()

    def save_embedding(self, files: bytes):
        """
        Generates the embedding list and saves it to the database.
        """
        try:
            embedding_list = UserLoginEmbeddingValidation.generate_embedding_list(files)
            avg_embedding_list = UserLoginEmbeddingValidation.average_embedding(
                embedding_list
            )
            self.user_embedding_data.save_user_embedding(self.uuid_, avg_embedding_list)

        except Exception as e:
            raise CustomException(e, sys) from e
