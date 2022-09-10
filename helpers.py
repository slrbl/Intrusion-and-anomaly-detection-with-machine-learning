# About: Utilities
# Author: walid.daboubi@gmail.com
# Version: 2.0 - 2022/08/14

import configparser
import sys
import numpy as np
from sklearn import tree, linear_model
import argparse
import pickle
import time
import re
import sys
from pandas import *

config = configparser.ConfigParser()
config.sections()
config.read('settings.conf')

MODEL = config['MODEL']['model']
FEATURES = config['FEATURES']['features'].split(',')
REGEX = '([(\d\.)]+) - - \[(.*?)\] "(.*?)" (\d+) (.+) "(.*?)" "(.*?)"'
SPECIAL_CHARS = "[$&+,:;=?@#|'<>.^*()%!-]"


# Encode a signle log line/Extract features
def encode_log_line(log_line):
    log_line = log_line.replace(',','_')
    log_line = re.match(REGEX,log_line).groups()
    # Extrating the URL
    url = log_line[2]
    # The features that are currently taken in account are the following
    return_code = log_line[3]
    params_number = len(url.split('&'))
    url_length = len(url)
    size = str(log_line[4]).rstrip('\n')
    url_depth = sum(1 for c in url if c == '/')
    upper_cases = sum(1 for c in url if c.isupper())
    lower_cases = sum(1 for c in url if c.islower())
    special_chars = sum(1 for c in url if c in SPECIAL_CHARS)
    size = 0 if '-' in size else int(size)
    if (int(return_code) > 0):
        log_line_data = {}
        log_line_data['size'] = int(size)
        log_line_data['params_number'] = int(params_number)
        log_line_data['length'] = int(url_length)
        log_line_data['return_code'] = int(return_code)
        log_line_data['upper_cases'] = int(upper_cases)
        log_line_data['lower_cases'] = int(lower_cases)
        log_line_data['special_chars'] = int(special_chars)
        log_line_data['url_depth'] = int(url_depth)
    else:
        log_line_data = None
    return url,log_line_data


def load_encoded_data(csv_data):
    data = read_csv(csv_data)
    labels = data['label']
    features = data.to_numpy()[:,list(range(0,len(FEATURES)))]
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
        print("Actual number of attacks: " + str(real_label_count))
        print("Predicted number of attacks: " + str(predicted_label_count))
        precision = predicted_label_count * 100 / real_label_count
        return precision


def save_model(model,label):
    model_file_name = 'MODELS/attack_classifier_{}_{}.pkl'.format(label,int(time.time()))
    pickle.dump(model, open(model_file_name, 'wb'))
    return model_file_name

def load_model(model_file):
    model = pickle.dump(model_file)
    return model
