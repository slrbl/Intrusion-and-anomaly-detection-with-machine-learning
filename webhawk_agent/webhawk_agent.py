import argparse
import platform
import requests
import socket
import configparser
import sys
import time

config = configparser.ConfigParser()
config.sections()
config.read('settings.conf')

parser = argparse.ArgumentParser(description="Webhawk agent v1.0\nUse this script to make detection on your endpoints.")

parser.add_argument(
    "-l", 
    "--log_file",
    help = "Path to the Apache log file to scan (e.g., ./SAMPLE_DATA/RAW_APACHE_LOGS/access.log.2022-12-22)", 
    required = True
)

args = parser.parse_args()

try:
    with open(args.log_file,'r') as f:
        logs=f.read()
except FileNotFoundError:
    print(f"Error: The file {args.log_file} does not exist.")
    sys.exit(1)
except PermissionError:
    print(f"Error: Permission denied when accessing {args.log_file}.")
    sys.exit(1)
except Exception as e:
    print(f"Unexpected error while reading the file: {e}")
    sys.exit(1)

data = {"hostname":socket.gethostname(),"logs_content":logs,"log_file":args.log_file}

try:
    start_time = time.time()
    print('Your logs are being processed..')
    url = "http://{}:{}/scan".format(
        config['WEBHAWK']['server_ip'],
        config['WEBHAWK']['server_port'],
    )
    user_agent = "WebhawkAgent/1.0 ({}; {}; {})".format(
        platform.system() or "unknown",
        platform.release() or "unknown",
        platform.machine() or "unknown",
    )
    response = requests.post(
        url,
        json=data,
        headers={"User-Agent": user_agent},
        timeout=300,
    )
    if not response.ok:
        print(
            f"Webhawk service returned HTTP {response.status_code}: {response.text}"
        )
        sys.exit(1)
    print(response.json())
    end_time = time.time()
    print(f"Took {end_time - start_time} seconds.")
except requests.RequestException as e:
    print(
        'Not able to reach webhawk service.\n'
        'Make sure that your webhawk server is up and that the detection service is running.\n'
        f'Details: {e}\n'
        'Exiting..'
    )
    sys.exit(1)
except ValueError as e:
    print(f"Invalid JSON response from webhawk service: {e}")
    sys.exit(1)
