
# About: Artificailly generate labeled data starting form raw http log file by adding rule based tags
# Author: walid.daboubi@gmail.com
# Version: 2.0 - 2022/08/14

#	A sample of lableled data:
# 	url_length,params_number,return_code,label, http_query
# 	49,1,404,1,GET /honeypot/bsidesdfw%20-%202014.ipynb HTTP/1.1
#       Label could be 1 (attack detected) or 0 (no attack detected)

# A HTTP LOG LINE SAMPLE
# 182.74.246.198 - - [01/Mar/2017:02:18:36 -0800] "GET /bootstrap/img/favicon.ico HTTP/1.1" 200 589 "http://www.secrepo.com/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36"

import argparse

from helpers import *

parser = argparse.ArgumentParser()
parser.add_argument('-l', '--log_file', help = 'The raw http log file', required = True)
parser.add_argument('-t', '--log_type', help = 'apache or nginx', required = True)
parser.add_argument('-d', '--dest_file', help = 'Destination to store the resulting csv file', required = True)
parser.add_argument('-a', '--artificial_label', help = 'Generate an artificial label for each log line', action='store_true')

args = vars(parser.parse_args())

log_file = args['log_file']
log_type = args['log_type']
dest_file = args['dest_file']
artificial_label = args['artificial_label']


# Encode all the data in http log file (access_log)
def encode_log_file(log_file):
	data = {}
	log_file = open(log_file, 'r')
	for log_line in log_file:
		log_line=log_line.replace(',','#').replace(';','#')
		_,log_line_data = encode_log_line(log_line,log_type)
		if log_line_data is not None:
			#data[url] = log_line_data
			data[log_line] = log_line_data
	return data


def encode_single_line(single_line,features):
    return ",".join((single_line[feature] for feature in features))


def add_artificial_labels(data,artificial_label):
	labelled_data_str = f"{config['FEATURES']['features']},label,log_line\n"
	for url in data:
		# U for unknown
		attack_label = 'U'
		if artificial_label:
			attack_label = '0'
			# Ths patterns are not exhaustive and they are here just for the simulation pupose
			patterns = ('honeypot', '%3b', 'xss', 'sql', 'union', '%3c', '%3e', 'eval')
			if any(pattern in url.lower() for pattern in patterns):
				attack_label = '1'
		labelled_data_str += f"{encode_single_line(data[url],FEATURES)}{attack_label},{url}"
	return len(data),labelled_data_str


def save_encoded_data(labelled_data_str,encoded_data_file,data_size):
	print(labelled_data_str)
	encoded_data_file.write(labelled_data_str)
	print('{} rows have successfully saved to {}'.format(data_size,dest_file))


data_size,labelled_data_str = add_simulation_labels(encode_log_file(log_file),artificial_label)
save_encoded_data(labelled_data_str,open(dest_file, 'w'),data_size)
