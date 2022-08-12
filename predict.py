# About: predict.py
# Author: walid.daboubi@gmail.com
# Version: 1.3 - 2021/10/30

from helpers import *

parser = argparse.ArgumentParser()
parser.add_argument('-l', '--log_line', help = 'The log line you want to assess', required = True)
parser.add_argument('-m', '--model', help = 'The trained model', required = True)

args = vars(parser.parse_args())
url,encoded = encode_log_line(args['log_line'])
formatted_encoded = []
for feature in FEATURES:
    formatted_encoded.append(encoded[feature])
model = pickle.load(open(args['model'], 'rb'))
prediction = model.predict([formatted_encoded])

print('The prediction for the log line:\n{}\nis:\n{}'.format(args['log_line'],prediction))
