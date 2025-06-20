
# 🦅 Webhawk 2.0

🔴 IMPORTANT The unsupervised Webhawk is now available as independent projet. Check it out at https://github.com/slrbl/unsupervised-learning-attack-detection-webhawk-catch


Machine Learning based web attacks detection.

<p align="center">  
  <img width="600" src="https://images.unsplash.com/photo-1607240376903-9a1f6d09330d?ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&ixlib=rb-1.2.1&auto=format&fit=crop&w=2340&q=80">
</p>

## About

Webhawk is an open source machine learning powered Web attack detection tool. It uses your web logs as training data. Webhawk offers a REST API that makes it easy to integrate within your SoC ecosystem. To train a detection model and use it as an extra security level in your organization, follow the following steps.

## Setup

### Using a Python virtual env

```shell
python -m venv webhawk_venv
source webhawk_venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Create a settings.conf file

Copy settings_template.conf file to settings.conf and fill it with the required parameters as the following.

```shell
[MODEL]
model:MODELS/the_model_you_will_train.pkl
[FEATURES]
features:length,params_number,return_code,size,upper_cases,lower_cases,special_chars,url_depth
```

## Unsupervised detection Usage

### Run the unsupervised detection script

Encoding is automatic for the unsupervised mode. You just need to run the catch.py script.
Get inspired from this example:

```shell
python catch.py -l ./SAMPLE_DATA/raw-http-logs-samples/may_oct_2022.log -t apache -j 10000 -s 5
```

## Supervised detection Usage

### Encode your http logs and save supervised detection results into a csv file

```shell
python encode.py -a -l ./SAMPLE_DATA/raw-http-logs-samples/aug_sep_oct_2021.log -d ./SAMPLE_DATA/labeled-encoded-data-samples/aug_sep_oct_2021.csv
```

Please note that two already encoded data files are available in ./SAMPLE_DATA/labeled-encoded-data-samples/, in case you would like to move directly to the next step.

### Train a model and test the prediction

Use the http log data from May to July 2021 to train a model, and test it with the data from August to October 2021.

```shell
python train.py -a 'dt' -t ./SAMPLE_DATA/labeled-encoded-data-samples/may_jun_jul_2021.csv -v ./SAMPLE_DATA/labeled-encoded-data-samples/aug_sep_oct_2021.csv
```

### Make a prediction for a single log line

```shell
python predict.py -m 'MODELS/the_model_you_will_train.pkl' -t 'apache' -l '198.72.227.213 - - [16/Dec/2018:00:39:22 -0800] "GET /self.logs/access.log.2016-07-20.gz HTTP/1.1" 404 340 "-" "python-requests/2.18.4"'
```

### REST API

#### Launch the API server

In order to use the API to need first to launch it's server as the following

```shell
python -m uvicorn api:app --reload --host 0.0.0.0 --port 8000
```

#### Make a prediction request

You can use the following code which based on Python 'requests' (the same in test_api.py) to make a prediction using the REST API

```python
import requests
import json
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
}
data = {
    'log_type':'apache',
    'http_log_line': '187.167.57.27 - - [15/Dec/2018:03:48:45 -0800] "GET /honeypot/Honeypot%20-%20Howto.pdf HTTP/1.1" 200 1279418 "http://www.secrepo.com/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.24 (KHTML, like Gecko) Chrome/61.0.3163.128 Safari/534.24 XiaoMi/MiuiBrowser/9.6.0-Beta"'
}
response = requests.post('http://127.0.0.1:8000/predict', headers=headers, data=json.dumps(data))
print(response.text)
```

It will return the following:

``` python
{"prediction":"0","confidence":"0.9975490196078431","log_line":"187.167.57.27 - - [15/Dec/2018:03:48:45 -0800] \"GET /honeypot/Honeypot%20-%20Howto.pdf HTTP/1.1\" 200 1279418 \"http://www.secrepo.com/\" \"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.24 (KHTML, like Gecko) Chrome/61.0.3163.128 Safari/534.24 XiaoMi/MiuiBrowser/9.6.0-Beta\""}
```

### Using Docker

#### Launch the API server (with Docker)

To launch the prediction server using docker

```shell
docker compose build
docker compose up
```

## Used sample data

The data you will find in SAMPLE_DATA folder comes from<br>
https://www.secrepo.com.

## Interesting data samples

https://www.kaggle.com/datasets/eliasdabbas/web-server-access-logs
https://dataverse.harvard.edu/dataset.xhtml?persistentId=doi:10.7910/DVN/3QBYB5

## Documentation

Details on how this tool is built could be found at
http://enigmater.blogspot.fr/2017/03/intrusion-detection-based-on-supervised.html

## TODO
Nothing for now.

## Reference

Silhouette Effeciency
<br>https://bioinformatics-training.github.io/intro-machine-learning-2017/clustering.html

<br>Optimal Value of Epsilon
<br>https://towardsdatascience.com/machine-learning-clustering-dbscan-determine-the-optimal-value-for-epsilon-eps-python-example-3100091cfbc

<br>Max curvature point
<br>https://towardsdatascience.com/detecting-knee-elbow-points-in-a-graph-d13fc517a63c

## Contribution

All feedbacks, testing and contribution are very welcome!
If you would like to contribute, fork the project, add your contribution and make a pull request.
