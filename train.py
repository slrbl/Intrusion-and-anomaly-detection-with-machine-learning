
# About: Use supervised learning logistic regression classifier to predict intrusion/suspecious activities in http logs
# Author: walid.daboubi@gmail.com
# Version: 1.3 - 2021/10/30

from utilities import *

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--traning_data', help = 'Training data', required = True)
    parser.add_argument('-v', '--testing_data', help = 'Testing data', required = True)
    parser.add_argument('-a', '--training_algorithm', help = '"lr" for logistic regression or "dr" for decision tree', required = True)
    return vars(parser.parse_args())

args = get_args()
traning_data = args['traning_data']
testing_data = args['testing_data']
training_algorithm = args['training_algorithm']

# Get training features and labeles
training_features, traning_labels = get_data_details(traning_data)
# Get testing features and labels
testing_features, testing_labels = get_data_details(testing_data)

if training_algorithm == 'lr':
    # LOGISTIC REGRESSION CLASSIFIER
    print("\n\n=-=-=-=-=-=-=- Logistic Regression Classifier -=-=-=-=-=-\n")
    attack_classifier = linear_model.LogisticRegression(solver='lbfgs', max_iter=100)
elif training_algorithm == 'dt':
    # DECISON TREE CLASSIFIER
    print("\n\n=-=-=-=-=-=-=- Decision Tree Classifier -=-=-=-=-=-=-=-\n")
    # Instanciate the classifier
    attack_classifier = tree.DecisionTreeClassifier()
else:
    print('{} is not recognized as a training algorithm')

if attack_classifier != None:
    # Train the model
    attack_classifier.fit(training_features, traning_labels)
    # Predict
    predictions = attack_classifier.predict(testing_features)
    print("The precision of the Logistic Regression Classifier is: " + str(get_accuracy(testing_labels,predictions, 1)) + "%")
    # Save the trained classifier
    model_location = save_model(attack_classifier,'lr')
    print("You model has been saved at {}".format(model_location))
