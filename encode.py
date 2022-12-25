
# About: Artificially generate labeled data starting form raw http log file by adding rule based tags
# Author: walid.daboubi@gmail.com
# Version: 2.0 - 2022/08/14

#	A sample of labelled data:
# 	url_length,params_number,return_code,label, http_query
# 	49,1,404,1,GET /honeypot/bsidesdfw%20-%202014.ipynb HTTP/1.1
#       Label could be 1 (attack detected) or 0 (no attack detected)

# A HTTP LOG LINE SAMPLE
# 182.74.246.198 - - [01/Mar/2017:02:18:36 -0800] "GET /bootstrap/img/favicon.ico HTTP/1.1" 200 589 "http://www.secrepo.com/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36"

import argparse

from utilities import *

parser = argparse.ArgumentParser()
parser.add_argument('-l', '--log_file', help = 'The raw http log file', required = True)
parser.add_argument('-t', '--log_type', help = 'apache or nginx', required = True)
parser.add_argument('-d', '--dest_file', help = 'Destination to store the resulting csv file', required = True)
parser.add_argument('-a', '--generate_artificial_label', help = 'Generate an artificial label for each log line', action='store_true')

args = vars(parser.parse_args())

log_file = args['log_file']
log_type = args['log_type']
dest_file = args['dest_file']
generate_artificial_label = args['generate_artificial_label']

data_size,labelled_data_str = construct_enconded_data_file(encode_log_file(log_file,log_type),generate_artificial_label)
save_encoded_data(labelled_data_str,dest_file,data_size)
