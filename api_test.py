import requests

with open("./SAMPLE_DATA/RAW_APACHE_LOGS/access.log.2017-05-24",'r') as f:
    logs=str(f.read())

params = {"placeholder":"nothing","logs_content":logs}
response=requests.post("http://127.0.0.1:8000/scan",json=params)
print(response.json())