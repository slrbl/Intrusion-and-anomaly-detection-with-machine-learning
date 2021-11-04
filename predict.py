# About: predict.py
# Author: walid.daboubi@gmail.com
# Version: 1.3 - 2021/10/30

from utilities import *

parser = argparse.ArgumentParser()
parser.add_argument('-l', '--log_line', help = 'The log line you want to assess', required = True)
parser.add_argument('-m', '--model', help = 'The trained model', required = True)

args = vars(parser.parse_args())
url,encoded = encode_single_log_line(args['log_line'])
formatte_encoded = []
for feature in FEATURES:
    formatte_encoded.append(encoded[feature])
model = pickle.load(open(args['model'], 'rb'))
prediction = model.predict([formatte_encoded])
print(prediction)
