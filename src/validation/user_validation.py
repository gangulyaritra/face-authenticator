import re
import sys
from typing import Optional
from passlib.context import CryptContext
from src.data_access.user_access import UserDataAccess
from src.entity.user import UserDetail
from src.exception import CustomException
from src.logger import logging

bcrypt_context = CryptContext(schemes=["sha256_crypt"])


class LoginValidation:
    def __init__(self, email_id: str, password: str):
        self.email_id = email_id
        self.password = password
        self.regex = re.compile(
            r"([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+"
        )

    def validate(self) -> bool:
        try:
            msg = ""
            if not self.email_id:
                msg += "Email is required."
            if not self.password:
                msg += "Password is required."
            if not self.is_email_valid():
                msg += "Invalid Email."
            return msg
        except Exception as e:
            raise e

    def is_email_valid(self) -> bool:
        return bool(re.fullmatch(self.regex, self.email_id))

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return bcrypt_context.verify(plain_password, hashed_password)

    def validate_login(self) -> dict:
        if len(self.validate()) != 0:
            return {"status": False, "msg": self.validate()}
        return {"status": True}

    def authenticate_user_login(self) -> Optional[str]:
        """
        Authenticates the User and returns the token.
        """
        try:
            logging.info("Authenticating User Details ......")

            if self.validate_login()["status"]:
                userdata = UserDataAccess()

                logging.info("Fetching User Details from the Database ......")
                user_login_val = userdata.get_user({"email_id": self.email_id})

                if not user_login_val:
                    logging.info("User does not exist.")
                    return False

                if not self.verify_password(self.password, user_login_val["password"]):
                    logging.info("Incorrect Password.")
                    return False

                logging.info("User Authenticated Successfully.")
                return user_login_val
            return False

        except Exception as e:
            raise CustomException(e, sys) from e


class RegisterValidation:
    def __init__(self, user: UserDetail) -> None:
        try:
            self.user = user
            self.email_regex = re.compile(
                r"([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+"
            )
            self.username_regex = re.compile(r"^[a-zA-Z]+$")
            self.phone_regex = re.compile(r"(0|91)?[6-9][0-9]{9}")
            self.uuid = self.user.uuid_
            self.userdata = UserDataAccess()
            self.bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        except Exception as e:
            raise e

    def validate(self) -> bool:
        """
        Checks validation conditions for user registration.
        """
        try:
            msg = ""
            if self.user.Name is None:
                msg += "Name is required."

            if self.user.username is None:
                msg += "Username is required."

            if self.user.email_id is None:
                msg += "Email is required."

            if self.user.phone_no is None:
                msg += "Phone Number is required."

            if self.user.password1 is None:
                msg += "Password is required."

            if self.user.password2 is None:
                msg += "Confirm Password is required."

            if not self.is_username_valid():
                msg += "Username must be alphabetic in length between 6 and 20."

            if not self.is_email_valid():
                msg += "Invalid Email."

            if not self.is_phone_valid():
                msg += "Phone No must be numeric of length 10."

            if not self.is_password_valid():
                msg += "Password length should be between 8 and 16."

            if not self.is_password_match():
                msg += "Password does not match."

            if not self.is_details_exists():
                msg += "User already exists."

            return msg

        except Exception as e:
            raise e

    def is_username_valid(self) -> bool:
        return bool(re.fullmatch(self.username_regex, self.user.username)) and (
            6 <= len(self.user.username) < 21
        )

    def is_email_valid(self) -> bool:
        return bool(re.fullmatch(self.email_regex, self.user.email_id))

    def is_phone_valid(self) -> bool:
        return bool(re.fullmatch(self.phone_regex, self.user.phone_no))

    def is_password_valid(self) -> bool:
        return len(self.user.password1) >= 8 and len(self.user.password2) <= 16

    def is_password_match(self) -> bool:
        return self.user.password1 == self.user.password2

    def is_details_exists(self) -> bool:
        uuid_val = self.userdata.get_user({"UUID": self.uuid})
        username_val = self.userdata.get_user({"username": self.user.username})
        emailid_val = self.userdata.get_user({"email_id": self.user.email_id})
        return username_val is None and emailid_val is None and uuid_val is None

    @staticmethod
    def get_password_hash(password: str) -> str:
        return bcrypt_context.hash(password)

    def validate_registration(self) -> bool:
        if len(self.validate()) != 0:
            return {"status": False, "msg": self.validate()}
        return {"status": True}

    def authenticate_user_registration(self) -> bool:
        """
        Saves the user details in the database only after validating the user details.
        """
        try:
            logging.info("Validating the user details while Registration ......")

            if self.validate_registration()["status"]:
                logging.info("Generating the Password Hash ......")
                hashed_password: str = self.get_password_hash(self.user.password1)

                user_data_dict: dict = {
                    "Name": self.user.Name,
                    "username": self.user.username,
                    "password": hashed_password,
                    "email_id": self.user.email_id,
                    "phone_no": self.user.phone_no,
                    "UUID": self.uuid,
                }

                logging.info("Saving the User Details in the Database ......")
                self.userdata.save_user(user_data_dict)
                logging.info("User Details get saved inside the database.")
                return {"status": True, "msg": "User Registered Successfully."}

            logging.info("Validation failed during Registration.")
            return {"status": False, "msg": self.validate()}

        except Exception as e:
            raise CustomException(e, sys) from e
