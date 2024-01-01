# Face Authentication App using FastAPI & MongoDB.

Build a cutting-edge Face Authentication System that leverages state-of-the-art [DeepFace](https://viso.ai/computer-vision/deepface/) algorithms for face detection and embedding generation. This system incorporates FastAPI endpoints, enabling seamless integration into various devices per specific needs.

## Project Architecture

<img width="840" alt="image" src="https://user-images.githubusercontent.com/57321948/195135349-9888d9ea-af5d-4ee2-8aa4-1e57342add05.png">

## Tech Stack & Infrastructure

1. Python
2. FastAPI
3. MongoDB
4. Dockers
5. AWS ECR & EC2
6. GitHub Actions for CI/CD

## Run the Application on a Desktop

#### Step 1: Create a Virtual Environment and Install Dependency.

```bash
# Clone the Repository.
git clone https://github.com/gangulyaritra/face-authenticator.git

# Create a Virtual Environment.
python3 -m venv venv

# Activate the Virtual Environment.
source venv/bin/activate

# Install the Dependencies.
pip install -r requirements.txt
```

#### Step 2: Run the Application Server.

```bash
python app.py
```

#### Step 3: Containerize the application using Docker.

```bash
docker build -t faceapp:latest -f Dockerfile .
```

#### Step 4: Run the Docker Image in the local system.

```bash
docker run -d -p 8000:8000 faceapp
```

## Authors

- [Aritra Ganguly](https://in.linkedin.com/in/gangulyaritra)

## License & Copyright

[MIT License](LICENSE)
