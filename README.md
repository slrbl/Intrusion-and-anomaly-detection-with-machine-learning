
# Web attacks detection with machine learning
## About
Machine learning algorithms applied on HTTP logs analysis to detect intrusions and suspicious activities.

## Usage
### Encode your http logs and save the result into a csv file
<code> $ python encode-raw-data.py -a -l ./DATA/raw-http-logs-samples/access-2018-12-15.log -d ./DATA/labeled-data-samples/access-2018-12-15.csv</code>

### Train a model and test the prediction
<code> $ python logistic-regression-classifier.py -t ./DATA/labeled-data-samples/all.csv -v ./DATA/labeled-data-samples/access-2018-12-15.csv </code>

### Make a prediction for a single URL
<code>#TODO</code>
<code> $ python predict.py URL </code>

### Make a prediction using a REST API
<code>#TODO</code>

## Documentation
Details could be found here:
<br>
http://enigmater.blogspot.fr/2017/03/intrusion-detection-based-on-supervised.html
