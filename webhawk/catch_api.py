
from catch import *
from enrich import advice_for_app, pull_model

def main(hostname,log_file,logs_content,user_agent=None):

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    get_stats('agent', user_agent)

    log_type = "apache"
    result = detect(
        log_file=log_file,
        log_content=logs_content,
        log_type=log_type,
        standardize=True,
    )
    if result is None:
        return 'Only one cluster was found'

    all_findings = result['findings']

    cves_finding=True
    ai_advice=True

    report=True
    sync_app=True

    logger.info('> Enriching findings..')

    if cves_finding==True or ai_advice==True:
        # Pull model if not available 
        pull_model(config['LLM']['model'],config['LLM']['url'])
        pull_model(config['JEV']['jev'],config['JEV']['url'])

    for finding in all_findings:
        data_is_ok=True 
        if ai_advice == True:
            logger.info('> Getting LLM advices..')
            logging.info('> Getting AI advice started')
            updated_finding = advice_for_app(finding)
            data_is_ok = updated_finding is not None

        if sync_app==True and data_is_ok:
            submit_to_app(hostname,updated_finding,log_file,log_type,config['LLM']['model'])
            
    # More details to be added to http return json
    return 'Success'