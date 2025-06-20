# app.py

from fastapi import FastAPI
from pydantic import BaseModel
from catch_api import main

app = FastAPI()
"""

with open("/Users/walid/Downloads/access.log.2025-04-22",'r') as f:
...         logs=str(f.read())
params = {"placeholder":"hello","logs_content":logs}
response=requests.post("http://127.0.0.1:8000/scan",json=params)
print(response.json())

"""
# Define input model
class NameInput(BaseModel):
    placeholder: str
    logs_content: str

# Health check endpoint
@app.get("/")
def root():
    print("-----------------------------")
    return {"message": "FastAPI service is running"}

# POST endpoint to log analysis
@app.post("/scan")
def scan(input: NameInput):
    print("-----------------------------")
    result = main(input.placeholder,input.logs_content)
    return {"result": result}

