# Web attacks detection with machine learning
Machine learning algorithms applied on HTTP logs analysis to detect intrusions and suspicious activities.

## How to use
### Encode your http logs and save the result in a file into csv file
<code> $ python label-raw-data.py -l ./raw-http-logs-samples/access-2018-12-15.log -d ./labeled-data-samples/access-2018-12-15.csv</code>

### Train a model and make a prediction
<code> $ python logistic-regression-classifier.py -t ./labeled-data-samples/all -v ./labeled-data-samples/access-2018-12-15.csv </code>

<br>
Details could be found here: 
<br>
http://enigmater.blogspot.fr/2017/03/intrusion-detection-based-on-supervised.html
