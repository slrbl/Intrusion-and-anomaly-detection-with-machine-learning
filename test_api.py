# This script is to be used to test the API

import requests
import json
import sys

headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
}
data = {
    'http_log_line': '187.167.57.27 - - [15/Dec/2018:03:48:45 -0800] "GET /honeypot/Honeypot%20-%20Howto.pdf HTTP/1.1" 200 1279418 "http://www.secrepo.com/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.24 (KHTML, like Gecko) Chrome/61.0.3163.128 Safari/534.24 XiaoMi/MiuiBrowser/9.6.0-Beta"'
}
try:
    response = requests.post('http://127.0.0.1:8000/predict', headers=headers, data=json.dumps(data))
    print (response.text)
except:
    print ('Something went wrong testing the API.\nExiting')
    sys.exit(1)

# It should return
#{"prediction":"0","confidence":"0.9975490196078431","log_line":"187.167.57.27 - - [15/Dec/2018:03:48:45 -0800] \"GET /honeypot/Honeypot%20-%20Howto.pdf HTTP/1.1\" 200 1279418 \"http://www.secrepo.com/\" \"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.24 (KHTML, like Gecko) Chrome/61.0.3163.128 Safari/534.24 XiaoMi/MiuiBrowser/9.6.0-Beta\""}
