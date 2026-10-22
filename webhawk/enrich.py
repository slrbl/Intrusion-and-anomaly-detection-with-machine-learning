import json
import logging

import requests

from utilities import config


def find_cves(findings):
    print('> Finding related CVEs')
    enriched_findings = []
    for finding in findings:
        # Only find CVE for the high severity findings
        if finding['severity'] == 'high':
            finding['cve'] = ''
            url = '{}/api/generate'.format(config['LLM']['url'])
            data = {
                "model": config['LLM']['model'],
                "prompt": (
                    "Extract all the CVE(s) from \"{}\". If don't find anything return \"None\" and do not return any text.  Return only a one line list of CVEs separated by commas.".format(finding['ai_advice'])
                ),
                "stream": False,
            }
            response = requests.post(url, json=data)
            if "CVE-" in response.json()['response']:
                finding['cve'] = response.json()['response'].replace(" ", "").replace(",", " ")
            else:
                finding['cve'] = ''

        enriched_findings.append(finding)
    return enriched_findings


def pull_model(model_name, url):
    response = requests.post('{}/api/pull'.format(url), json={"name": model_name}, stream=True)
    if response.status_code == 200:
        print(f"Pulling model: {model_name}")
        for line in response.iter_lines():
            if line:
                print(line.decode('utf-8'))
        print("Model pulled successfully.")
    else:
        print(f"Failed to pull model: {response.status_code}")
        print(response.text)


def get_llm_insights(findings):
    enriched_findings = []
    count = len(findings)

    for current, finding in enumerate(findings, start=1):
        # JEV classification to check if this is a false positive
        logging.info(f"> Checking if FP {current}/{count}")
        data = {
            "model": config["JEV"]["jev"],
            "state": finding["log_line"],
            "questions": {
                "is_false_positive": {
                    "type": "noul",
                    "instructions": "Does the state contain a potential attack trace ?",
                    "criteria": {
                        "true": "The state doesn't contain attack traces",
                        "false": "The state contains attack traces",
                    },
                }
            },
        }
        url = "{}{}".format(config["JEV"]["url"], config["JEV"]["jev_endpoint"])
        response = requests.post(url, json=data)
        is_fp_prob = response.json()["answers"]["is_false_positive"]["noul"]
        is_confirmed_prob = 1 - is_fp_prob

        # Get more insights if this is not a false positive
        if is_confirmed_prob >= float(config['JEV']['confirmed_threshold']):
            url = "{}{}".format(config["LLM"]["url"], config["LLM"]["model_endpoint"])
            logging.info(f"> Getting AI advice {current}/{count}")
            finding["ai_advice"] = ""

            prompt = f"{config['LLM']['prompt']} {finding['log_line']}"
            data = {
                "model": config["LLM"]["model"],
                "prompt": prompt,
                "stream": False,
            }
            response = requests.post(url, json=data)
            finding["ai_advice"] = response.json()["response"]
        else:
            finding["ai_advice"] = (
                '{"potential_attack_attempt":false,"details":"This is a potential'
                ' false positive","severity":"low","CVE":"","owasp":'
                ' "","recommendation":"Nothing to do."}'
            )

        enriched_findings.append(finding)

    return enriched_findings


def advice_for_app(finding):
    """Run JEV and the LLM, then split the JSON advice into app fields."""
    updated_finding = get_llm_insights([finding])
    raw_ai_advice = updated_finding[0]['ai_advice']

    try:
        json_ai_advice = json.loads(raw_ai_advice.replace('\\', '').replace("'", "\'"))
    except Exception:
        logging.info('> JSON parsing issue encountred')
        logging.info(raw_ai_advice)
        return None

    updated_finding[0]['ai_advice'] = json_ai_advice['details']
    if json_ai_advice['potential_attack_attempt'] == False:
        updated_finding[0]['severity'] = 'low'
    else:
        updated_finding[0]['severity'] = json_ai_advice['severity']

    updated_finding[0]['cve'] = json_ai_advice['CVE']
    updated_finding[0]['recommendation'] = json_ai_advice['recommendation']
    updated_finding[0]['owasp'] = json_ai_advice['owasp']
    return updated_finding
