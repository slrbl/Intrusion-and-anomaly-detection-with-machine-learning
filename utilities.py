# About: Utilities
# Author: walid.daboubi@gmail.com
# Version: 1.3 - 2021/10/30

import sys
import numpy as np
from sklearn import tree, linear_model
import argparse
import pickle
import time
import re
import sys

REGEX = '([(\d\.)]+) - - \[(.*?)\] "(.*?)" (\d+) (.+) "(.*?)" "(.*?)"'

def get_data_details(csv_data):
        print(csv_data)
        data = np.genfromtxt(csv_data, delimiter = ",")
        features = data[:, [0, 1, 2]]
        labels = data[:, 3]
        return features, labels

def get_accuracy(real_labels, predicted_labels, fltr):
        real_label_count = 0.0
        predicted_label_count = 0.0
        for real_label in real_labels:
                if real_label == fltr:
                        real_label_count += 1
        for predicted_label in predicted_labels:
                if predicted_label == fltr:
                        predicted_label_count += 1
        print("Real number of attacks: " + str(real_label_count))
        print("Predicted number of attacks: " + str(predicted_label_count))

        precision = predicted_label_count * 100 / real_label_count
        return precision

# Encode a signle log line
def encode_single_log_line(log_line):
	log_line = log_line.replace(',','_')
	log_line = re.match(REGEX,log_line).groups()
	url = log_line[2]
	return_code = log_line[3]
	param_number = len(url.split('&'))
	url_length = len(url)
	size = str(log_line[4]).rstrip('\n')
	if '-' in size:
		size = 0
	else:
		size = int(size)
	if (int(return_code) > 0):
		log_line_data = {}
		log_line_data['size'] = int(size)
		log_line_data['param_number'] = int(param_number)
		log_line_data['length'] = int(url_length)
		log_line_data['return_code'] = int(return_code)
	else:
		log_line_data = None
	return url,log_line_data

def save_model(model,label):
    model_file_name = 'MODELS/attack_classifier_{}_{}.pkl'.format(label,int(time.time()))
    pickle.dump(model, open(model_file_name, 'wb'))
    return model_file_name

def load_model(model_file):
    model = pickle.dump(model_file)
    return model
