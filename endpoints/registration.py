import os
from typing import List
from pydantic import BaseModel
from fastapi import APIRouter, File, Request
from starlette import status
from starlette.responses import JSONResponse
from src.validation.user_embedding_validation import UserRegisterEmbeddingValidation
from src.validation.user_validation import RegisterValidation
from src.entity.user import UserDetail


class Register(BaseModel):
    Name: str
    username: str
    email_id: str
    phone_no: str
    password1: str
    password2: str


router = APIRouter(
    prefix="/faceapp",
    tags=["Registration"],
    responses={"401": {"description": "UNAUTHORIZED!!!"}},
)

os.environ["CUDA_VISIBLE_DEVICES"] = "-1"


@router.post(
    "/register_user",
    response_class=JSONResponse,
    response_description="Register New User.",
)
async def register_user(request: Request, register: Register):
    """
    POST request to register a new user.
    """
    try:
        name = register.Name
        username = register.username
        password1 = register.password1
        password2 = register.password2
        email_id = register.email_id
        phone_no = register.phone_no

        # Add UUID to the session.
        user = UserDetail(name, username, email_id, phone_no, password1, password2)
        request.session["uuid"] = user.uuid_

        # Validation of User Input Data.
        user_registration = RegisterValidation(user)

        validate_regitration = user_registration.validate_registration()
        if not validate_regitration["status"]:
            msg = validate_regitration["msg"]
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"status": False, "message": msg},
            )

        # Save User if Validation is Successful.
        validation_status = user_registration.authenticate_user_registration()

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"status": True, "message": validation_status["msg"]},
            headers={"UUID": user.uuid_},
        )

    except Exception as e:
        raise e


@router.post("/register_embedding", response_description="Register Face Embeddings.")
async def register_embedding(
    request: Request,
    files: List[bytes] = File(description="Multiple files as UploadFile"),
):
    """
    POST request to add face embeddings of the user during registration.
    """
    try:
        # Get the UUID from the session.
        uuid = request.session.get("uuid")
        if uuid is None:
            msg = "Error in Storing Embedding in Database."
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"status": False, "message": msg},
            )

        user_embedding_validation = UserRegisterEmbeddingValidation(uuid)

        # Save and store the face embeddings.
        user_embedding_validation.save_embedding(files)

        # Deletes the Current Session.
        del request.session["uuid"]

        msg = "Embedding Stored Successfully in Database."
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"status": True, "message": msg},
            headers={"UUID": uuid},
        )

    except Exception as e:
        raise e
