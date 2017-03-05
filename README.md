# Intrusion Detection With Machine Learning
Machine learning algorithms applied on log analysis to detect intrusions and suspicious activities.
### Extract features for raw http logs
$ python label-raw-data.py /my_logs_folder/jan/access_log_training.log

$ python label-raw-data.py /my_logs_folder/jan/access_log_testing.log
### Label the extracted features 
In order to make classification possible the traning data have to be labled so each line of code will be identified as an attack or not.
Labelling consists of adding an extra value to each data line: 0 for "normal logs" and 1 for suspecious logs.

### Apply classifier 
#### Decision Tree Classifier
#### Logistic Regression classifier

