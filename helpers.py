# About: Utilities
# Author: walid.daboubi@gmail.com
# Version: 2.0 - 2022/08/14

import configparser
import pickle
import re
import sys
import time

import pandas as pd

config = configparser.ConfigParser()
config.sections()
config.read('settings.conf')

MODEL = config['MODEL']['model']
FEATURES = config['FEATURES']['features'].split(',')
SPECIAL_CHARS = set("[$&+,:;=?@#|'<>.^*()%!-]")


# Encode a signle log line/Extract features
def encode_log_line(log_line,log_type):
    log_line = log_line.replace(',','_')
    # log_type is apache for the moment
    if log_type in config['LOG']:
        log_fomat = config['LOG'][log_type]
    else:
        print('Log type \'{}\' not defined'.format(log_type))
        sys.exit(1)
    if log_fomat in [None,'']:
        print('Log format \'{}{}\' is emtpy'.format(log_type,log_fomat))
        sys.exit(1)
    try:
        log_line = re.match(log_fomat,log_line).groups()
    except:
        print('Something went wrong parsing the log fomrat \'{}\''.format(log_type))
        sys.exit(0)
    # Extrating the URL
    url = log_line[2]
    # The features that are currently taken in account are the following
    return_code = log_line[3]
    params_number = len(url.split('&'))
    url_length = len(url)
    size = str(log_line[4]).rstrip('\n')
    url_depth = url.count("/")
    upper_cases = sum(1 for c in url if c.isupper())
    lower_cases = len(url) - upper_cases
    special_chars = sum(1 for c in url if c in SPECIAL_CHARS)
    size = 0 if '-' in size else int(size)
    if (int(return_code) > 0):
        log_line_data = {}
        log_line_data['size'] = size
        log_line_data['params_number'] = params_number
        log_line_data['length'] = url_length
        log_line_data['return_code'] = int(return_code)
        log_line_data['upper_cases'] = upper_cases
        log_line_data['lower_cases'] = lower_cases
        log_line_data['special_chars'] = special_chars
        log_line_data['url_depth'] = int(url_depth)
    else:
        log_line_data = None
    return url, log_line_data



def load_encoded_data(csv_data):
    data = pd.read_csv(csv_data)
    labels = data['label']
    features = data.to_numpy()[:, list(range(0, len(FEATURES)))]
    return features, labels


def get_accuracy(real_labels, predicted_labels, fltr):
    real_label_count = sum(1 for label in real_labels if label == fltr)
    predicted_label_count = sum(1 for label in predicted_labels if label == fltr)
    print("Actual number of attacks: " + "{:.1f}".format(real_label_count))
    print("Predicted number of attacks: " + "{:.1f}".format(predicted_label_count))
    precision = predicted_label_count * 100 / real_label_count
    return precision


def save_model(model, label):
    model_file_name = f'MODELS/attack_classifier_{label}_{int(time.time())}.pkl'
    pickle.dump(model, open(model_file_name, 'wb'))
    return model_file_name


def load_model(model_file):
    model = pickle.dump(model_file)
    return model
