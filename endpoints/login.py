import os
from datetime import datetime, timedelta, timezone
from jose import jwt
from typing import List, Optional
from pydantic import BaseModel
from passlib.context import CryptContext
from fastapi import APIRouter, File, Request, Response, status
from starlette.responses import JSONResponse, RedirectResponse

from src.validation.user_validation import LoginValidation
from src.validation.user_embedding_validation import UserLoginEmbeddingValidation
from src.data_access.user_access import UserDataAccess
from src.data_access.user_embedding_access import UserEmbeddingAccess
from src.constant import ALGORITHM, SECRET_KEY


class Login(BaseModel):
    email_id: str
    password: str


router = APIRouter(
    prefix="/faceapp",
    tags=["Login"],
    responses={"401": {"description": "UNAUTHORIZED!!!"}},
)

os.environ["CUDA_VISIBLE_DEVICES"] = "-1"


def create_access_token(
    uuid: str, username: str, expires_delta: Optional[timedelta] = None
) -> str:
    # Create the access token.
    try:
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=15)

        encode = {"sub": uuid, "username": username, "exp": expire}
        return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

    except Exception as e:
        raise e


@router.post("/token")
async def login_for_access_token(response: Response, login: Login) -> dict:
    # Set the access token.
    try:
        user_validation = LoginValidation(login.email_id, login.password)
        user: Optional[str] = user_validation.authenticate_user_login()

        if not user:
            return {"status": False, "uuid": None, "response": response}

        token_expires = timedelta(minutes=15)
        token = create_access_token(
            user["UUID"], user["username"], expires_delta=token_expires
        )

        response.set_cookie(key="access_token", value=token, httponly=True)
        return {"status": True, "uuid": user["UUID"], "response": response}

    except Exception as e:
        msg = "Failed to set the access token."
        response = JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND, content={"message": msg}
        )
        return {"status": False, "uuid": None, "response": response}


@router.post(
    "/login_user", response_class=JSONResponse, response_description="User Login."
)
async def login_user(request: Request, login: Login):
    """
    POST request to login a user.
    """
    try:
        response = JSONResponse(
            status_code=status.HTTP_200_OK, content={"message": "Login Successful."}
        )

        token_response = await login_for_access_token(response=response, login=login)

        if not token_response["status"]:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"status": False, "message": "Incorrect Credentials."},
            )

        # Add UUID to the session.
        response.headers["uuid"] = token_response["uuid"]
        request.session["uuid"] = response.headers["uuid"]
        return response

    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": False, "message": "User NOT Found."},
        )


@router.post(
    "/authenticate_embedding", response_description="Authenticate Face Embeddings."
)
async def authenticate_embedding(
    request: Request,
    files: List[bytes] = File(description="Multiple files as UploadFile"),
):
    """
    POST request to validate face embeddings of the user after login.
    """
    try:
        # Get the UUID from the session.
        uuid = request.session.get("uuid")
        if uuid is None:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"status": False, "message": "No User is currently logged in."},
            )

        user_embedding_validation = UserLoginEmbeddingValidation(uuid)

        # Authenticate User Embeddings.
        if user_simmilariy_status := user_embedding_validation.compare_embedding(files):
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"status": True, "message": "User is Authenticated."},
            )
        else:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"status": False, "message": "User is NOT Authenticated."},
            )

    except Exception as e:
        raise e


@router.get("/fetch_user", response_description="Retrieve User Data.")
async def fetch_user(request: Request):
    """
    GET request to fetch user data.
    """
    try:
        # Get the UUID from the session.
        uuid = request.session.get("uuid")
        if uuid is None:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"status": False, "message": "No User is currently logged in."},
            )

        # Fetch Data from Database.
        userdata = UserDataAccess()
        user = userdata.get_user({"UUID": uuid})

        user.pop("_id")
        user.pop("UUID")
        user.pop("password")

        if user is not None:
            return JSONResponse(user)
        else:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"status": False, "message": "Failed to Retrieve User Data."},
            )

    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": False, "message": "User account doesn't exist."},
        )


@router.post("/logout_user", response_description="User Logout.")
async def logout_user(request: Request):
    """
    POST request to logout a user.
    """
    try:
        # Get the UUID from the session.
        uuid = request.session.get("uuid")
        if uuid is None:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"status": False, "message": "No User is currently logged in."},
            )

        msg = f"{uuid} has been logged out."
        response = RedirectResponse(
            url="/docs/", status_code=status.HTTP_302_FOUND, headers={"msg": msg}
        )

        # Deletes the Current Session and Cookies.
        response.delete_cookie(key="access_token")
        del request.session["uuid"]

        response = JSONResponse(
            status_code=status.HTTP_200_OK, content={"status": True, "message": msg}
        )
        return response

    except Exception as e:
        raise e


@router.put("/change_password", response_description="Set New Password.")
async def change_password(request: Request, new_password: str, confirm_password: str):
    """
    PUT request to update user password.
    """
    try:
        # Get the UUID from the session.
        uuid = request.session.get("uuid")
        if uuid is None:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"status": False, "message": "No User is currently logged in."},
            )

        bcrypt_context = CryptContext(schemes=["sha256_crypt"])

        if (
            new_password == confirm_password
            and len(new_password) >= 8
            and len(confirm_password) <= 16
        ):
            # Updates User Password.
            userdata = UserDataAccess()
            userdata.update_user(
                {"UUID": uuid},
                {"password": bcrypt_context.hash(confirm_password)},
            )

            # Deletes the Current Session.
            del request.session["uuid"]

            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"status": True, "message": "Password Changed Successfully."},
                headers={"UUID": uuid},
            )
        else:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"status": False, "message": "Invalid Password."},
            )

    except Exception as e:
        raise e


@router.delete("/delete_account", response_description="Account Deletion.")
async def delete_account(request: Request, login: Login):
    """
    DELETE request to delete a user account and its corresponding embeddings.
    """
    try:
        # Get the UUID from the session.
        uuid = request.session.get("uuid")
        if uuid is None:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"status": False, "message": "No User is currently logged in."},
            )

        # Get the UUID from the input credentials.
        user_validation = LoginValidation(login.email_id, login.password)
        user: Optional[str] = user_validation.authenticate_user_login()

        # If Session UUID matches the input credentials UUID, then perform account deletion.
        if uuid == user["UUID"]:
            # Deletes User Data.
            userdata = UserDataAccess()
            delete_user = userdata.delete_user({"UUID": user["UUID"]})

            # Deletes Embedding Data.
            userembedding = UserEmbeddingAccess()
            delete_embedding = userembedding.delete_user_embedding(user["UUID"])

            # Deletes the Current Session.
            del request.session["uuid"]

            if delete_user.deleted_count == 1 or delete_embedding.deleted_count == 1:
                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content={
                        "status": True,
                        "message": "Account Deleted Successfully.",
                    },
                    headers={"UUID": user["UUID"]},
                )

            else:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"status": False, "message": "Account Deletion Failed."},
                )

    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": False, "message": "User account doesn't exist."},
        )
