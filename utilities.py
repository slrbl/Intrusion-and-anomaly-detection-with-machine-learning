# About: Utilities
# Author: walid.daboubi@gmail.com
# Version: 2.0 - 2022/08/14

import configparser
import re
import ast
import sys
import time
import psutil
import logging
import requests
import socket

def get_process_col_locations(header_line, list_col_names):
    col_locations = {}
    for idx, col_name in enumerate(list_col_names):
        col_width = len(col_name)
        col_locations[col_name] = {}

        if idx == 0:
            col_locations[col_name]['start_idx'] = 0
        else:
            col_locations[col_name]['start_idx'] = col_locations[list_col_names[idx-1]]['end_idx']

        if idx+1 < len(list_col_names):
            re_pattern = r"(?<={})(.*?)(?={})".format(col_name, list_col_names[idx+1])
        else:
            re_pattern = r"(?<={})(.*?)".format(col_name)
        whitespaces = re.findall(re_pattern, header_line)
        col_width += len(whitespaces[0])
        col_locations[col_name]['end_idx'] = col_locations[col_name]['start_idx']+col_width
    return col_locations

def parse_process_file(process_file):
    with open(process_file) as f:
        processes_lines = f.readlines()

    summary_line_pattern = r'^\D*:'
    is_header_line = False
    is_header_line_seen = False
    process_data = []

    for line in processes_lines:
        process_dict = {}

        is_summary_line = re.match(summary_line_pattern, line)
        if is_summary_line:
            is_header_line_seen = False

        is_header_line = True if 'PID' in line and '%CPU' in line else False
        if is_header_line:
            header_line = line.strip()
            list_col_names = header_line.split()
            col_locations = get_process_col_locations(header_line, list_col_names)
            is_header_line = False
            is_header_line_seen = True
            continue

        if is_header_line_seen:
            for col_name in col_locations:
                col_start_idx = col_locations[col_name]['start_idx']
                col_end_idx = col_locations[col_name]['end_idx']
                process_value = line[col_start_idx:col_end_idx].strip()
                try:
                    process_dict[col_name] = float(process_value)
                except:
                    process_dict[col_name] = process_value

            process_data.append(process_dict)
    return process_data

def encode_single_line(single_line,features):
    return ",".join((str(single_line[feature]) for feature in features))


# Encode a single log line/Extract features
def encode_log_line(log_line,log_type,indices,categorical_fractions,encoding_type):

    # log_type is apache for the moment
    try:
        log_format = config['LOG'][log_type+"_regex"]    
        log_names = ast.literal_eval(config['LOG'][log_type+"_names"])
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

    # Getting log details for APACHE
    # Extracting the URL

    ip = log_line[log_names.index("ip")]
    http_query = log_line[log_names.index("query")].split(' ')[0]
    url="".join(log_line[log_names.index("query")].split(' ')[1:])
    # The features that are currently taken in account are the following
    return_code = log_line[log_names.index("code")]
    return_code = 0 if '-' in return_code else return_code
    params_number = len(url.split('&'))
    url_length = len(url)
    size = str(log_line[log_names.index("size")]).rstrip('\n')
    url_depth = url.count("/")
    upper_cases = sum(1 for c in url if c.isupper())
    lower_cases = len(url) - upper_cases
    special_chars = sum(1 for c in url if c in SPECIAL_CHARS)
    size = 0 if '-' in size else int(size)
    user_agent=log_line[log_names.index("user_agent")]
    if (int(return_code) > 0):
        log_line_data = {}
        log_line_data['size'] = size
        log_line_data['params_number'] = params_number
        log_line_data['length'] = url_length
        log_line_data['return_code'] = float(return_code)
        log_line_data['upper_cases'] = upper_cases
        log_line_data['lower_cases'] = lower_cases
        log_line_data['special_chars'] = special_chars
        log_line_data['url_depth'] = float(url_depth)

        if encoding_type == 'label_encoding':
            log_line_data['ip'] = indices['ips'].index(ip)+1
            log_line_data['http_query'] = 100*(indices['http_queries'].index(http_query)+1)
            log_line_data['user_agent'] = indices['user_agents'].index(user_agent)+1

        if encoding_type == 'fraction_encoding':
            log_line_data['http_query']=categorical_fractions['http_queries'][http_query]
            log_line_data['user_agent']=categorical_fractions['user_agents'][user_agent]
            log_line_data['ip']=categorical_fractions['ips'][ip]

    else:
        log_line_data = None
    return url, log_line_data

# Encode all the data in http log file (access_log)
def encode_logs(log_file_content,log_type,encoding_type):
    data = {}
    log_file_content=list(log_file_content)
    indices = get_categorical_indices(log_file_content,log_type)
    categorical_fractions = get_categorical_fractions(log_file_content,log_type)
    for log_line in log_file_content:
        log_line=log_line.replace(',','#').replace(';','#')
        _,log_line_data = encode_log_line(log_line,log_type,indices,categorical_fractions,encoding_type)
        if log_line_data is not None:
            #data[url] = log_line_data
            data[log_line] = log_line_data
    return data


def get_categorical_indices(log_file_content,log_type):
    incides = {
        'http_queries':[],
        'user_agents':[],
        'ips':[]
    }
    for log_line in log_file_content:
        log_line=log_line.replace(',','#').replace(';','#')
        try:
            log_format = config['LOG'][log_type+"_regex"]
            log_names = ast.literal_eval(config['LOG'][log_type+"_names"])
        except:
            print('Log type \'{}\' not defined. \nMake sure "settings.conf" file exits and the log concerned type is defined.\nExiting'.format(log_type))
            sys.exit(1)
        try:
            log_line = re.match(log_format,log_line).groups()
        except:
            print('Log type \'{}\' doesn\'t fit your log fomat.\nExiting'.format(log_type))
            sys.exit(1)

        http_query=log_line[log_names.index("query")].split(' ')[0]
        if http_query not in incides['http_queries']:
            incides['http_queries'].append(http_query)

        user_agent=log_line[log_names.index("user_agent")]
        if user_agent not in incides['user_agents']:
            incides['user_agents'].append(user_agent)

        ip=log_line[log_names.index("ip")]
        if ip not in incides['ips']:
            incides['ips'].append(ip)

    return incides


def get_categorical_fractions(log_file_content,log_type):
    fractions = {
        'http_queries':{},
        'user_agents':{},
        'ips':{},
    }
    data_count=0
    for log_line in log_file_content:
        log_line=log_line.replace(',','#').replace(';','#')
        try:
            log_format = config['LOG'][log_type+"_regex"]
            log_names = ast.literal_eval(config['LOG'][log_type+"_names"])
        except:
            print('Log type \'{}\' not defined. \nMake sure "settings.conf" file exits and the log concerned type is defined.\nExiting'.format(log_type))
            sys.exit(1)
        try:
            log_line = re.match(log_format,log_line).groups()
        except:
            print('Log type \'{}\' doesn\'t fit your log fomat.\nExiting'.format(log_type))
            sys.exit(1)
        data_count+=1
        
        
        http_query=log_line[log_names.index("query")].split(' ')[0]
        if http_query not in fractions['http_queries']:
            fractions['http_queries'][http_query] = 1
        else:
            fractions['http_queries'][http_query] +=1

        user_agent=log_line[log_names.index("user_agent")]
        if user_agent not in fractions['user_agents']:
            fractions['user_agents'][user_agent] = 1
        else:
            fractions['user_agents'][user_agent] += 1

        ip=log_line[log_names.index("ip")]
        if user_agent not in fractions['ips']:
            fractions['ips'][ip] = 1
        else:
            fractions['ips'][ip] += 1
    for fraction in fractions:
        for categorical_fraction in fractions[fraction]:
            fractions[fraction][categorical_fraction] = fractions[fraction][categorical_fraction]/(data_count*1.)
    return fractions

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




def gen_report(findings,log_file,log_type,llm_model):
    report_file_path='./REPORTS/scan_result_{}.html'.format(log_file.split('/')[-1].replace('.','_'))
    gmt_time=time.strftime("%d/%m/%y at %H:%M:%S GMT", time.gmtime())
    report_str="""
        <head>
            <style>
                table {
                    table-layout: fixed;
                    width: 100%;
                }
                td {
                  padding: 5px;
                }
                th {
                  text-align:left;
                  padding: 10px;
                  background-color: whitesmoke;
                }
                div {
                  font-family:monospace;
                  padding: 50px;
                }
            </style>
        </head>
    """

    if not log_type == 'os_processes':
        report_str+="""
            <div>
                <table width="100%">
                    <tr>
                        <td width="50%">
                            <h1>Webhawk Catch Report</h1>
                            <p>
                                Unsupervised learning Web logs/OS processes attack detection.
                            </p>
                            Date: {}
                            <br>
                            Log file: {}
                            <br>
                            Log type: {} logs
                            <br>
                            <h3>Findings: {}</h3>
                        </td>
                        <td>
                            <img src='{}'/>
                        </td>
                </tr>
                </table>
            <table width="100%">
                <tr style="background:gainsboro;padding:10px">
                    <td style="width:5%">Severity</td>
                    <td style="width:8%">Related CVE(s)</td>
                    <td style="width:4%">{}</td>
                    <td style="width:40%">LLM Insights({})</td>
                    <td style="width:43%">Log line</td>
                </tr>

        """.format(gmt_time,log_file,log_type,len(findings),report_file_path.replace('result','plot').replace('html','png').replace('./REPORTS','.'),'Line#',llm_model)
    else:
        report_str+="""
            <div>
                <h1>Webhawk Catch Report</h1>
                <p>
                    Unsupervised learning Web logs/OS processes attack detection.
                </p>
                Date: {}
                <br>
                Log file: {}
                <br>
                Log type: {} logs
                <br>
                <h3>Findings: {}</h3>
            <table>
                <tr style="background:whitesmoke;padding:10px">
                    <td>Severity</td>
                    <td>{}</td>
                    <td>Log line</td>
                    <td>Process details</td>
                </tr>
        """.format(gmt_time,log_file,log_type,len(findings), 'PID')

    for finding in findings:
        severity=finding['severity']
        #cve = finding['cve'] if 'cve' in finding else 'Not found'

        cves=''
        if 'cve' in finding and finding['cve']!='':
            cve_list = finding['cve'].split(' ')
            if len(cve_list)>0:
                cve_list.reverse()
                for cve in cve_list:
                    if 'CVE-' in cve:
                        cves += "<a href='https://nvd.nist.gov/vuln/detail/{}'>{}</a><br>".format(cve,cve)
        else:
            cves='<i>No CVE found</i>'

        if severity == 'medium':
            background='orange'
        if severity == 'high':
            background='OrangeRed'

        if not log_type == 'os_processes':
            ai_advice=finding['ai_advice'] if 'ai_advice' in finding else 'N/A'
            report_str+="""
                <tr>
                    <td style="background:{};text-align:center;color:whitesmoke">{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td style="word-break: break-word; white-space: normal;">{}</td>
                </tr>
            """.format(background,severity.capitalize(),cves,finding['log_line_number']+1,ai_advice,finding['log_line'])
        else:
            report_str+="""
                <tr>
                    <td style="background:{};text-align:center;color:whitesmoke">{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                </tr>
            """.format(background,severity.capitalize(),finding['pid'],finding['log_line'], finding['process_details'])

    report_str+="</table></div>"

    with open(report_file_path,'w') as result_file:
        result_file.write(report_str)
    return report_file_path

def submit_to_app(findings,log_file,log_type,llm_model):
    for finding in findings:
        severity=finding['severity']
        #cve = finding['cve'] if 'cve' in finding else 'Not found'

        cves=''
        if 'cve' in finding and finding['cve']!='':
            cve_list = finding['cve'].split(' ')
            if len(cve_list)>0:
                cve_list.reverse()
                for cve in cve_list:
                    if 'CVE-' in cve:
                        cves += "<a href='https://nvd.nist.gov/vuln/detail/{}'>{}</a><br>".format(cve,cve)
        else:
            cves='<i>No CVE found</i>'

        if severity == 'medium':
            background='orange'
        if severity == 'high':
            background='OrangeRed'

        ai_advice=finding['ai_advice'] if 'ai_advice' in finding else 'N/A'

        url = config['WEBAPP']['url']

        headers = {
            "Content-Type": "application/json"
        }
        data = {
            "incident": {
                "cves": cves,
                "severity":severity,
                "status":'Open',
                "verdict":'Unknown',
                "llm_insights":ai_advice,
                "log_line":finding['log_line_number'],
                "log_line_content":finding['log_line'],
                "attack_vector": "Web",
                "host":socket.gethostname()
            }
        }

        response = requests.post(url, headers=headers, json=data)

        print(response.status_code)
        print(response.json())


def get_process_details(pid):
    process_details_attributes = ast.literal_eval(config['PROCESS_DETAILS']['attributes'])
    try:
        process = psutil.Process(pid)
        return process.as_dict(attrs=process_details_attributes)
    except Exception as e:
        print(f'Cannot get process details about PID: {pid} becasue {e}')
        return {}

config = configparser.ConfigParser()
config.sections()
config.read('settings.conf')

SPECIAL_CHARS = set("[$&+,:;=?@#|'<>.^*()%!-]")

try:
    FEATURES = config['FEATURES']['features'].split(',')
except:
    print('No features defined. Make sure the file "settings.conf" exists and training/prediction features are defined.')
    print('Exiting..')
    sys.exit(1)
