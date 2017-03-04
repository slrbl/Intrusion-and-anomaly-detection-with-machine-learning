# Version: 1.0 - 2017/03/04
# About:Generate labeled data starting form raw http log file
#	A sample of lableled data: 
# 	url_length,param_number,return_code,label, http_query
# 	49,1,404,1,GET /honeypot/bsidesdfw%20-%202014.ipynb HTTP/1.1
#       Label could be 1 (attack detected) or 0 (no attack detected)



import re
import sys

# A HTTP LOG LINE SAMPLE
# 182.74.246.198 - - [01/Mar/2017:02:18:36 -0800] "GET /bootstrap/img/favicon.ico HTTP/1.1" 200 589 "http://www.secrepo.com/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36"

log_file=sys.argv[1]
dest_file=sys.argv[2]

data={}
regex = '([(\d\.)]+) - - \[(.*?)\] "(.*?)" (\d+) (.+) "(.*?)" "(.*?)"'

#Retrieve data form a a http log file (access_log)
log_file=open(log_file,'r')
for log_line in log_file:
	log_line=re.match(regex,log_line).groups()
	size=str(log_line[4]).rstrip('\n')
	return_code=log_line[3]
	url=log_line[2]
	param_number=len(url.split('&'))
	url_length=len(url)
	if '-' in size:
		size=0
	else:
		size=int(size)

	if (int(return_code)>0):
		charcs={}
		charcs['size']=int(size)
		charcs['param_number']=int(param_number)
		charcs['length']=int(url_length)
		charcs['return_code']=int(return_code)
		data[url]=charcs

labeled_data=open(dest_file,'w')

for w in data:
	attack='0'
	patterns=['honeypot','%3b','xss','sql','union','%3c','%3e','eval']
	if any(pattern in w.lower() for pattern in patterns):
		attack='1'
	data_row=str(data[w]['length'])+','+str(data[w]['param_number'])+','+str(data[w]['return_code'])+','+attack+','+w+'\n'
	labeled_data.write(data_row)

print str(len(data))+' rows have successfully saved to '+dest_file
