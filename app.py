import uvicorn
from fastapi import FastAPI
from starlette import status
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse
from endpoints import login, registration


app = FastAPI()


@app.get("/")
def read_root():
    return RedirectResponse(url="/docs", status_code=status.HTTP_302_FOUND)


app.include_router(registration.router)

app.include_router(login.router)

app.add_middleware(SessionMiddleware, secret_key="!secret")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
