
# About: Use supervised learning logistic regression classifier to predict intrusion/suspicious activities in http logs
# Author: walid.daboubi@gmail.com
# Version: 2.0 - 2022/08/14

import argparse
import sys

from sklearn import linear_model, tree

from helpers import *


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--training_data', help = 'Training data', required = True)
    parser.add_argument('-v', '--testing_data', help = 'Testing data', required = True)
    parser.add_argument('-a', '--training_algorithm', help = '"lr" for logistic regression or "dr" for decision tree', required = True)
    return vars(parser.parse_args())

args = get_args()

training_data = args['training_data']
testing_data = args['testing_data']
training_algorithm = args['training_algorithm']

# Get training features and labels
training_features, training_labels = load_encoded_data(training_data)
# Get testing features and labels
testing_features, testing_labels = load_encoded_data(testing_data)

# Logistic regression model
if training_algorithm == 'lr':
    print("\n\n=-=-=-=-=-=-=- Logistic Regression Classifier -=-=-=-=-=-\n")
    attack_classifier = linear_model.LogisticRegression()
# Decision tree model
elif training_algorithm == 'dt':
    print("\n\n=-=-=-=-=-=-=- Decision Tree Classifier -=-=-=-=-=-=-=-\n")
    attack_classifier = tree.DecisionTreeClassifier()
else:
    print('{} is not recognized as a training algorithm'.format(training_algorithm))

try:
    # Train the model
    attack_classifier.fit(training_features, training_labels)
    # Predict
    predictions = attack_classifier.predict(testing_features)
    print("The precision of the detection model is: " + str(get_accuracy(testing_labels,predictions, 1)) + " %")
    # Save the trained classifier
    model_location = save_model(attack_classifier,'lr')
    print("You model has been saved at {}".format(model_location))
except Exception as e:
    print('Something went wrong training the model.\nExiting.', e)
    sys.exit(1)
