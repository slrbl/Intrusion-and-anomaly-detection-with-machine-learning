# About: Utilities
# Author: walid.daboubi@gmail.com
# Version: 2.0 - 2022/08/14

import configparser
import pickle
import re
import sys
import time

import pandas as pd


# Encode a single log line/Extract features
def encode_log_line(log_line,log_type):
    log_line = log_line.replace(',','_')
    # log_type is apache for the moment
    try:
        log_format = config['LOG'][log_type]
    except:
        print('Log type \'{}\' not defined. \nMake sure "settings.conf" file exits and the log concerned type is defined.\nExiting'.format(log_type))
        sys.exit(1)
    if log_format in [None,'']:
        print('Log format \'{}{}\' is empty'.format(log_type,log_format))
        sys.exit(1)
    try:
        log_line = re.match(log_format,log_line).groups()
    except:
        print('Something went wrong parsing the log format \'{}\''.format(log_type))
        sys.exit(0)
    # Extracting the URL
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


def encode_single_line(single_line,features):
    return ",".join((str(single_line[feature]) for feature in features))

# Encode all the data in http log file (access_log)
def encode_log_file(log_file,log_type):
	data = {}
	log_file = open(log_file, 'r')
	for log_line in log_file:
		log_line=log_line.replace(',','#').replace(';','#')
		_,log_line_data = encode_log_line(log_line,log_type)
		if log_line_data is not None:
			#data[url] = log_line_data
			data[log_line] = log_line_data
	return data


def construct_enconded_data_file(data,set_simulation_label):
	labelled_data_str = f"{config['FEATURES']['features']},label,log_line\n"
	for url in data:
		# U for unknown
		attack_label = 'U'
		if set_simulation_label==True:
			attack_label = '0'
			# Ths patterns are not exhaustive and they are here just for the simulation purpose
			patterns = ('honeypot', '%3b', 'xss', 'sql', 'union', '%3c', '%3e', 'eval')
			if any(pattern in url.lower() for pattern in patterns):
				attack_label = '1'
		labelled_data_str += f"{encode_single_line(data[url],FEATURES)},{attack_label},{url}"
	return len(data),labelled_data_str


def save_encoded_data(labelled_data_str,dest_file,data_size):
    print(labelled_data_str)
    with  open(dest_file, 'w') as encoded_data_file:
        encoded_data_file.write(labelled_data_str)
    print('{} rows have successfully saved to {}'.format(data_size,dest_file))


def load_model(model_file):
    model = pickle.dump(model_file)
    return model


config = configparser.ConfigParser()
config.sections()
config.read('settings.conf')


try:
    MODEL = config['MODEL']['model']
except:
    print('No model defined. Make sure the file "settings.conf" exists and a model is defined')
    print('Continuing..')


try:
    FEATURES = config['FEATURES']['features'].split(',')
except:
    print('No features defined. Make sure the file "settings.conf" exists and training/prediction features are defined.')
    print('Exiting..')
    sys.exit(1)


SPECIAL_CHARS = set("[$&+,:;=?@#|'<>.^*()%!-]")
