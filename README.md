
# Webhawk/Catch 3.0

Unsupervised, AI-augmented detection of attacks in application logs.

Presented at [Black Hat Arsenal USA 2023](docs/blackhat/BHUS23-PPT-Arsenal-Slide-Webhawk-WD_v3.pdf), Black Hat Arsenal USA 2025, and DEF CON Labs Bahrain 2025.

Author: [Walid Daboubi](https://github.com/slrbl)

<p align="center">  
  <img width="70%" src="https://github.com/slrbl/Intrusion-and-anomaly-detection-with-machine-learning/blob/master/docs/hawk.jpg">
  <br>
  Image source:https://unsplash.com/photos/i4Y9hr5dxKc (Mathew Schwartz)
</p>

## Abstract

Webhawk is an ML/AI powered detection tool designed to automatically identify attack traces in application logs (Eg: HTTP) without relying on preset rules. Using unsupervised machine learning, Webhawk groups log entries into clusters and detects outliers that may indicate potential attack traces. After detection, Webhawk leverages Agentic AI to provide detailed analysis and actionable recommendations.

Webhawk comes with a user-friendly web interface. Webhawk UI allows SOC team members to easily manage and review the detections. Detection results can also be fed to your existing SOC ecosystem (Eg: SIEM) thanks to the builtin API.

## Technical details 

Webhawk transforms raw logs into numerical data and applies Principal Component Analysis (PCA) to extract the most relevant features (such as user-agent, IP address, and the number of transmitted parameters). It then uses the DBSCAN (Density-Based Spatial Clustering of Applications with Noise) algorithm to cluster log lines and identify anomalous points, which may represent potential attack traces.

Advanced users can fine-tune Webhawk through a set of configuration options that optimize the clustering algorithm—for example, by adjusting the minimum number of points per cluster or the maximum distance between points within the same cluster.

Once detections are complete, the results are sent to an LLM of your choice for in-depth analysis and actionable recommendations. Webhawk leverages agentic AI design patterns to ensure that the insights and suggestions delivered to users provide meaningful, real-world value.

To get data from your endpoints, Webhawk provide an agent that your can easily deploy on every endpoint. Once launched, this agent gets logs from the concerned file and transmit them to the detection engine via the API.

The tool is easy to deploy using Docker Compose, which simplifies the installation of the three main components: the detection engine, the web application, and the LLM services.

<p align="center">  
  <img width="100%" src="https://github.com/slrbl/Intrusion-and-anomaly-detection-with-machine-learning/blob/master/docs/webhawk_design_v3.png">
</p>

## Telemetry

Webhawk collects anonymous telemetry when you run the CLI or the agent. It records only how the tool is used, so the project can be improved. Your log contents are not collected.

## Production setup

### Configuring webhawk/settings.conf file
Details about setting up this configuration file can be found in Development setup/Create a settings.conf file section below.

### Building and launching Docker services 

```shell
docker compose build
docker compose up
```

Once the above command are launched, three services will be running:
#### Webhawk
This is the service used for detection, it takes as input a log file and it return detections.
#### Ollama 
This service is used to make prompt for LLMs and getting response.
#### Webhawk web application 
This service is used to run the web application where the detections results will be treated by cyber analysts.

<p align="center">  
  <img width="100%" src="https://github.com/slrbl/Intrusion-and-anomaly-detection-with-machine-learning/blob/master/docs/webhawk_app_screenshot_2.png">
</p>

<p align="center">  
  <img width="100%" src="https://github.com/slrbl/Intrusion-and-anomaly-detection-with-machine-learning/blob/master/docs/webhawk_app_screenshot_3.png">
</p>

##### Launching Docker services for the first time 
If you are launching the Docker services after the first build then you need to expect some delay for the first agent request. In fact this delay is related to downloading of the selected Ollama  model, note that this delay will disappear if you have already added this model pulling to ./ollama_starter.sh.

### Webhawk Agent
To make detection within your endpoints you need to configure and execute webhawk agent which is available in ./webhawk_agent.
```shell
python webhawk_agent.py -l ./HTTP_LOGS/access.log.2025-02-08
```
Once the execution is done new incidents will appear in Webhawk web application.


## Development setup

The goal of this section is to help using webhawk detection, without using the web application. 
For the next steps you need to be in ./webhawk folder.

### Using a Python virtual env

```shell
python -m venv webhawk_venv
source webhawk_venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Create a settings.conf file

Copy settings.conf.template file to settings.conf and fill it with the required parameters as the following.

```shell
[FEATURES]
features:length,params_number,return_code,size,upper_cases,lower_cases,special_chars,url_depth,user_agent,http_query,ip

[LOG]
apache_regex:([(\d\.)]+) - - \[(.*?)\] "(.*?)" (\d+) (.+) "(.*?)" "(.*?)"
apache_names:["ip","date","query","code","size","referrer","user_agent"]

nginx_regex:([(\d\.)]+) - - \[(.*?)\] "(.*?)" (\d+) (\d+) (.+) "(.*?)" "(.*?)"
nginx_names:["ip","date","query","code","size","referrer","user_agent"]

http_regex:^(\d*?\.\d*?)\t.*?\t(.*?)\t.*?\t.*?\t.*?\t.*?\t(.*?\t.*?\t.*?\t.*?)\t(.*?)\t.*?\t(.*?)\t(.*?)\t.*$
http_names:["date","ip","query","user_agent","size","code"]

apache_error:
nginx_error:

[PROCESS_DETAILS]
attributes:['status', 'num_ctx_switches', 'memory_full_info', 'connections', 'cmdline', 'create_time', 'num_fds', 'cpu_percent', 'terminal', 'ppid', 'cwd', 'nice', 'username', 'cpu_times', 'memory_info', 'threads', 'open_files', 'name', 'num_threads', 'exe', 'uids', 'gids', 'memory_percent', 'environ']

[CVE]
source:https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=
year_threshold:YYYY

[LLM]
url:http://ollama:11434 #if using docker compose
url:http://localhost:11434 #if not using docker compose
model:intigration/analyzer:latest #or select a model of your choice
prompt:Analyze this web log line for malicious activity. Provide a brief one pragraph (less than 60 words) as a response. Indidate if there is a known related attack or vulnerability. Do not start with 'This log line'

[WEBAPP]
webhawk_ui
url:http://webhawk_ui:8080/api/v1/incidents #if using docker compose
url:http://localhost:8080/api/v1/incidents #if not using docker compose
```

## Unsupervised detection Usage

### Catch.py script

```shell
python catch.py -h
usage: catch.py [-h] -l LOG_FILE -t LOG_TYPE [-e EPS] [-s MIN_SAMPLES] [-j LOG_LINES_LIMIT] [-y OPT_LAMDA] [-m MINORITY_THRESHOLD] [-p] [-o] [-r] [-z] [-b] [-c] [-v] [-a] [-q]

options:
  -h, --help            show this help message and exit
  -l, --log_file LOG_FILE
                        The raw log file
  -t, --log_type LOG_TYPE
                        apache, http, nginx or os_processes
  -e, --eps EPS         DBSCAN Epsilon value (Max distance between two points)
  -s, --min_samples MIN_SAMPLES
                        Minimum number of points with the same cluster. The default value is 2
  -j, --log_lines_limit LOG_LINES_LIMIT
                        The maximum number of log lines of consider
  -y, --opt_lamda OPT_LAMDA
                        Optimization lambda step
  -m, --minority_threshold MINORITY_THRESHOLD
                        Minority clusters threshold
  -p, --show_plots      Show informative plots
  -o, --standardize_data
                        Standardize feature values
  -r, --report          Create a HTML report
  -z, --opt_silouhette  Optimize DBSCAN silouhette
  -b, --debug           Activate debug logging
  -c, --label_encoding  Use label encoding instead of frequeny encoding to encode categorical features
  -v, --find_cves       Find the CVE(s) that are related to the attack traces
  -a, --get_ai_advice   Get AI advice on the detection
  -q, --quick_scan      Only most critical detection (no minority clusters)
  -f, --submit_to_app   Submit the finding to Webhawk app
```


### Example with apache logs

Encoding is automatic for the unsupervised mode. You just need to run the catch.py script.
Get inspired from this example:

```shell
python catch.py -l ./SAMPLE_DATA/RAW_APACHE_LOGS/access.log.2022-12-22 --log_type apache --standardize_data --report --find_cves --get_ai_advice
```

The output of this command is:

<p align="center">  
  <img width="100%" src="https://github.com/slrbl/Intrusion-and-anomaly-detection-with-machine-learning/blob/master/docs/execution_screeshot.png">
</p>

<p align="center">  
  <img width="80%" src="https://github.com/slrbl/Intrusion-and-anomaly-detection-with-machine-learning/blob/master/docs/figure_1.png">
</p>

<p align="center">  
  <img width="80%" src="https://github.com/slrbl/Intrusion-and-anomaly-detection-with-machine-learning/blob/master/docs/figure_2.png">
</p>

<p align="center">  
  <img width="100%" src="https://github.com/slrbl/Intrusion-and-anomaly-detection-with-machine-learning/blob/master/docs/report_screenshot.png">
</p>


### Example with OS processes
Before running the catch.py, you need to generate a .txt file containing the OS process statistics by taking advantage of top command:
```shell
top > PATH/os_processes.txt
```

You can then run the catch.py to detect potential abnormal OS processes:
```shell
python catch.py -l PATH/os_processes.txt --log_type os_processes --show_plots --standardize_data --report
```

## Webhawk API
Webhawk API can be launched using the following command:
```shell
uvicorn app:app --reload
```
Testing the API using:
The API can be tested using the script api_test.py or by launching the follwoing python commands:
```python
import requests
with open("./SAMPLE_DATA/RAW_APACHE_LOGS/access.log.2017-05-24",'r') as f:
    logs=str(f.read())
params = {"hostname":"nothing","logs_content":logs}
response=requests.post("http://127.0.0.1:8000/scan",json=params)
print(response.json())
```

## Used sample data

The data you will find in ./SAMPLE_DATA folder comes from<br>
https://www.secrepo.com.

## Generating your own testing data

You can alos generate test data using the script ./log_generator/apache_http_log_generator.py

## Interesting data samples

https://www.kaggle.com/datasets/eliasdabbas/web-server-access-logs
https://dataverse.harvard.edu/dataset.xhtml?persistentId=doi:10.7910/DVN/3QBYB5


## TODO
Adding more details to the high level design digaram
Adding finding one by one to Webhawk UI
Enhancing the UI
Decoupling data transfer using Kafka (or equivalent)


## Reference

Silhouette Effeciency
<br>https://bioinformatics-training.github.io/intro-machine-learning-2017/clustering.html

<br>Optimal Value of Epsilon
<br>https://towardsdatascience.com/machine-learning-clustering-dbscan-determine-the-optimal-value-for-epsilon-eps-python-example-3100091cfbc

<br>Max curvature point
<br>https://towardsdatascience.com/detecting-knee-elbow-points-in-a-graph-d13fc517a63c

## Contribution

All feedback, testing, and contributions are very welcome! If you would like to contribute, fork the project, add your changes, and submit a pull request.
