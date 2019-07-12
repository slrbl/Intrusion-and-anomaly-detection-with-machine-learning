
# About: Use supervised learning logistic regression classifier to predict intrusion/suspecious activities in http logs
# Author: walid.daboubi@gmail.com
# Version: 1.2 - 2019/07/13

from utilities import *

args = get_args()
traning_data = args['traning_data']
testing_data = args['testing_data']

# Get training features and labeles
training_features, traning_labels = get_data_details(traning_data)

# Get testing features and labels
testing_features, testing_labels = get_data_details(testing_data)

# LOGISTIC REGRESSION CLASSIFIER
print "\n\n=-=-=-=-=-=-=- Logistic Regression Classifier -=-=-=-=-=-\n"

attack_classifier = linear_model.LogisticRegression(C = 1e5)
attack_classifier.fit(training_features, traning_labels)

predictions = attack_classifier.predict(testing_features)
print "The precision of the Logistic Regression Classifier is: " + str(get_occuracy(testing_labels,predictions, 1)) + "%"
