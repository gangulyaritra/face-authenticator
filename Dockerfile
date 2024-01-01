FROM python:3.10-slim-bullseye
RUN apt update -y && apt install awscli -y
WORKDIR /app
COPY . /app
RUN apt-get install ffmpeg libsm6 libxext6 -y
RUN pip install -r requirements.txt
CMD ["python3", "app.py"]