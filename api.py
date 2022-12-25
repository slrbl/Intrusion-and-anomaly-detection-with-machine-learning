# About: api.py
# Author: walid.daboubi@gmail.com
# Version: 1.3 - 2021/11/02

# To be launched as the following
# python3 -m uvicorn api:app --reload --host 0.0.0.0 --port 8000

from fastapi import FastAPI
from pydantic import BaseModel

from utilities import *


class HttpLogQueryModel(BaseModel):
    http_log_line : str

app = FastAPI()

@app.post('/predict')
def predict(data: HttpLogQueryModel):
    datadict = data.dict()
    _,encoded = encode_log_line(datadict['http_log_line'],datadict['log_type'])
    model = pickle.load(open(MODEL, 'rb'))
    formatted_encoded = [encoded[feature] for feature in FEATURES]
    prediction = int(model.predict([formatted_encoded])[0])
    confidence = model.predict_confidence([formatted_encoded])[0][prediction]
    return {
        'prediction': str(prediction),
        'confidence':str(confidence),
        'log_line':datadict['http_log_line']
    }
