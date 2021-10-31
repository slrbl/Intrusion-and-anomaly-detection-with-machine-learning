
# Web attacks detection with machine learning
## About
Machine learning algorithms applied on HTTP logs analysis to detect intrusions and suspicious activities.

## Usage
### Encode your http logs and save the result into a csv file
<code> $ python encode.py -a -l ./DATA/raw-http-logs-samples/access-2018-12-15.log -d ./DATA/labeled-data-samples/access-2018-12-15.csv</code>

### Train a model and test the prediction
<code> $ python train.py -a 'lr' -t ./DATA/labeled-data-samples/all.csv -v ./DATA/labeled-data-samples/access-2018-12-15.csv</code>

### Make a prediction for a single log line
<code> $ python predict.py -l '198.72.227.213 - - [16/Dec/2018:00:39:22 -0800] "GET /self.logs/access.log.2016-07-20.gz HTTP/1.1" 404 340 "-" "python-requests/2.18.4"'</code>

### Make a prediction using a REST API
<code>#TODO</code>

## Documentation
Details could be found here:
<br>
http://enigmater.blogspot.fr/2017/03/intrusion-detection-based-on-supervised.html
