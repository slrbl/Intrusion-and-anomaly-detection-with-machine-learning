# app.py

from fastapi import FastAPI, Request
from pydantic import BaseModel
from catch_api import main

app = FastAPI()
"""
with open("/Users/walid/Downloads/access.log.2025-04-22",'r') as f:
...         logs=str(f.read())
params = {"hostname":"hello","logs_content":logs}
response=requests.post("http://127.0.0.1:8000/scan",json=params)
print(response.json())
"""

# Define input model
class NameInput(BaseModel):
    hostname: str
    log_file: str
    logs_content: str

# Health check endpoint
@app.get("/")
def root():
    return {"message": "FastAPI service is running"}

# POST endpoint to log analysis
@app.post("/scan")
def scan(input: NameInput, request: Request):
    result = main(
        input.hostname,
        input.log_file,
        input.logs_content,
        request.headers.get("user-agent"),
    )
    return {"result": result}

