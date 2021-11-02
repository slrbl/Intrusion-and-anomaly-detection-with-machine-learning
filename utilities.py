# About: Utilities
# Author: walid.daboubi@gmail.com
# Version: 1.3 - 2021/10/30

import configparser
import sys
import numpy as np
from sklearn import tree, linear_model
import argparse
import pickle
import time
import re
import sys

REGEX = '([(\d\.)]+) - - \[(.*?)\] "(.*?)" (\d+) (.+) "(.*?)" "(.*?)"'
SPECIAL_CHARS = "[$&+,:;=?@#|'<>.^*()%!-]"

config = configparser.ConfigParser()
config.sections()
config.read('settings.conf')

MODEL = config['MODEL']['model']
FEATURES = config['FEATURES']['features'].split(',')

def get_data_details(csv_data):
        print(csv_data)
        data = np.genfromtxt(csv_data, delimiter = ",")
        features = data[:, [0-(len(FEATURES)-1)]]
        labels = data[:, len(FEATURES)]
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
    print(log_line)
    log_line = log_line.replace(',','_')
    log_line = re.match(REGEX,log_line).groups()
    url = log_line[2]
    return_code = log_line[3]
    param_number = len(url.split('&'))
    url_length = len(url)
    size = str(log_line[4]).rstrip('\n')
    depth = sum(1 for c in url if c == '/')
    upper_cases = sum(1 for c in url if c.isupper())
    lower_cases = sum(1 for c in url if c.islower())
    special_chars = sum(1 for c in url if c in SPECIAL_CHARS)
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
        log_line_data['upper_cases'] = int(upper_cases)
        log_line_data['lower_cases'] = int(lower_cases)
        log_line_data['special_chars'] = int(special_chars)
        log_line_data['depth'] = int(depth)
    else:
        log_line_data = None
    print(log_line_data)
    return url,log_line_data

def save_model(model,label):
    model_file_name = 'MODELS/attack_classifier_{}_{}.pkl'.format(label,int(time.time()))
    pickle.dump(model, open(model_file_name, 'wb'))
    return model_file_name

def load_model(model_file):
    model = pickle.dump(model_file)
    return model
