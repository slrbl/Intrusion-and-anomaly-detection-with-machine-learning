import requests

headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
}

data = '{ "joke": "The category of this joke is hard to guess since it s not a joke" }'

response = requests.post('http://127.0.0.1:8000/predict', headers=headers, data=data)

print (response.text)

# It should return
# {"prediction":"Puns","score":0.08488171436343636}
