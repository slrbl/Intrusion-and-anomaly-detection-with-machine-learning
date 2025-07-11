
# Webhawk/Catch 3.0

Unsupervised Machine Learning web attacks detection.


<p align="center">  
  <img width="100%" src="https://github.com/slrbl/unsupervised-learning-attack-detection-webhawk-catch/blob/master/IMAGES/hawk.jpg">
  Image source:https://unsplash.com/photos/i4Y9hr5dxKc (Mathew Schwartz)
</p>

## About

Webhawk/Catch helps automatically finding web attack traces in HTTP logs and abnormal OS processes without using any preset rules. Based on the usage of Unsupervised Machine Learning, Catch groups log lines into clusters, and detects the outliers that it considers as potentially attack traces. 

The tool is able to parse both raw HTTP log files (Apache, Nginx, ...) and files including OS statistics (generated by top command). The tool takes these files as input and returns a report with a list of findings. 

Catch uses PCA (Principal Component Analysis) technique to select the most relevant features (Example: user-agent, IP address, number of transmitted parameters, etc.. ). Then, it runs DBSCAN (Density-Based Spatial Clustering of Applications with Noise) algorithm to get all the possible log line clusters and anomalous points (potential attack traces).  

Advanced users can fine tune Catch based on a set of options that help optimising the clustering algorithm (Example: minimum number of points by cluster, or the maximum distance between two points within the same cluster).

The current version of Webhawk/Catch generates an easy-to-read HTML report which includes all the findings, and the severity of each one.

Webhawk/Catch is an open-source tool. Catch is the unsupervised version of Webhawk which is a supervised machine learning based cyber-attack detection tool. In contrary to the supervised Webhawk, Catch can be used without manually pertaining a model, the thing that makes it a lightweight and flexible solution to easily identify potential attack traces.  Catch is available as an independent repository in Github, it is also included as part of Webhawk which is starred 125 times and forked 68 times.

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

[LLM]
url:http://localhost:11434/api/generate
model:llama3.2
prompt:a prompt of yout choice to check the log line
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
  <img width="100%" src="https://github.com/slrbl/Intrusion-and-anomaly-detection-with-machine-learning/blob/master/IMAGES/execution_screeshot.png">
</p>

<p align="center">  
  <img width="80%" src="https://github.com/slrbl/Intrusion-and-anomaly-detection-with-machine-learning/blob/master/IMAGES/figure_1.png">
</p>

<p align="center">  
  <img width="80%" src="https://github.com/slrbl/Intrusion-and-anomaly-detection-with-machine-learning/blob/master/IMAGES/figure_2.png">
</p>

<p align="center">  
  <img width="100%" src="https://github.com/slrbl/Intrusion-and-anomaly-detection-with-machine-learning/blob/master/IMAGES/report_screenshot.png">
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
params = {"placeholder":"nothing","logs_content":logs}
response=requests.post("http://127.0.0.1:8000/scan",json=params)
print(response.json())
```

## Deployment using Docker 
Webhawk can be as webservice using Docker as the following:
```shell
docker compose build
docker compose up
```
At this point the API can be used as mentioned above.

## Used sample data

The data you will find in ./SAMPLE_DATA folder comes from<br>
https://www.secrepo.com.

## Interesting data samples

https://www.kaggle.com/datasets/eliasdabbas/web-server-access-logs
https://dataverse.harvard.edu/dataset.xhtml?persistentId=doi:10.7910/DVN/3QBYB5


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

All feedback, testing, and contributions are very welcome! If you would like to contribute, fork the project, add your changes, and submit a pull request.
