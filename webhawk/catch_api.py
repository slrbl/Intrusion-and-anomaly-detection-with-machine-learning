
from catch import *
import json

def main(hostname,log_file,logs_content,user_agent=None):

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    get_stats('agent', user_agent)

    log_type="apache"
    LOG_LINES_LIMIT=1000000
    FEATURES = [
        'params_number',
        #'size', # Stopped using size because it makes a lot of false positive detections
        'length',
        'upper_cases',
        'lower_cases',
        'special_chars',
        'url_depth',
        'user_agent',
        'http_query',
        'ip',
        'return_code',
        'log_line',
        ]
    encoding_type='fraction_encoding'
    standardize_data=True
    eps=None
    opt_silouhette=False
    opt_lamda=None
    min_samples=None
    minority_threshold=None

    LAMBDA = float(opt_lamda) if opt_lamda is not None else 0.01
    THRESHOLD = int(minority_threshold) if minority_threshold else 5

    #log_file_content=open(log_file, 'r')
    log_file_content=logs_content

    logger.info('> Getting data..')

    data = get_data(
        log_file, # No log_file as the logs as provided as a string
        log_file_content,
        log_type,
        LOG_LINES_LIMIT,
        FEATURES,
        encoding_type
        )
    
    # convert to a dataframe
    if log_type != 'os_processes':
        dataframe = data.to_numpy()[:,list(range(0,len(FEATURES)-1))]
    else:
        dataframe = data
    
    logger.info('> Preporcessing data..')
    # Standarize data
    if standardize_data:
        dataframe = sklearn.preprocessing.StandardScaler().fit_transform(dataframe)

    # Dimensiality reduction to 2d using PCA
    pca = sklearn.decomposition.PCA(n_components=2)
    principal_components_df = pca.fit_transform(dataframe)
    dataframe = pd.DataFrame(
        data = principal_components_df,
        columns = ['pc_1', 'pc_2'])
    

     # Getting or setting epsilon
    if eps == None:
        logging.info('\n> No Epsilon input. Finding the max sorted neighbors curvature point and use it as Epsilon')
        automatic_max_curve_point = find_max_curvature_point(dataframe, eps)
        selected_eps = automatic_max_curve_point
        logging.info('{}{}'.format(4*' ',automatic_max_curve_point))
    else:
        selected_eps=float(eps)


    
    if opt_silouhette:
        logging.info('\n> Optimizing Epsilon to get the best BDSCAN Silhouette Coefficient')
        best_silouhette, best_eps_for_silouhette = optimize_silouhette_coefficient(selected_eps, dataframe, LAMBDA)
        logging.info('{}{}'.format(4*' ', best_eps_for_silouhette))
        selected_eps = best_eps_for_silouhette

    logger.info('> Detection..')
    # Use dbscan for clustering and train the model

    if eps == None and min_samples == None:
        dbscan = sklearn.cluster.DBSCAN(eps=selected_eps)
    elif eps == None:
        dbscan = sklearn.cluster.DBSCAN(eps=selected_eps, min_samples=int(min_samples))
    elif min_samples == None:
        dbscan = sklearn.cluster.DBSCAN(eps=selected_eps)
    else:
        dbscan = sklearn.cluster.DBSCAN(eps=selected_eps, min_samples=int(min_samples))
    dbscan_model = dbscan.fit(dataframe)


    # Check the number of labels (if 1 then try without EPS value)
    if len(set(dbscan_model.labels_)) == 1:
        logging.info('{}Only one cluster was found using the value {} as epsilon'.format(4*' ',selected_eps))
        logging.info('{}Trying without epsilon'.format(4*' '))
        dbscan = sklearn.cluster.DBSCAN()
        dbscan_model = dbscan.fit(dataframe)
    if len(set(dbscan_model.labels_)) == 1:
        logging.info('{}Only one cluster was found without an epsilon value. Exiting.'.format(4*' '))
        sys.exit(0)

    # Get point labels
    labels = dbscan_model.labels_

    elements_by_cluster = find_elements_by_cluster(labels)
    number_of_clusters = len(elements_by_cluster.values())

    # Get top minority clusters
    minority_clusters = get_minority_clusters(elements_by_cluster,THRESHOLD)

    # Outliers are considred as high severity findings

    high_findings = catch(labels,data,-1, log_type)
    if len(high_findings)>0:
        logging.info ('\n\n\n\n    '+100*'/'+'   HIGH Severity findings   '+100*'\\')
        print_findings(high_findings, log_type)

    # Points belonging to minority clusters are considred as medium severity findings
    medium_findings=[]
    for label in minority_clusters:
        if label != -1:
            medium_findings += catch(labels,data,label, log_type)

    if len(medium_findings) > 0:
        logging.info ('\n\n\n\n    '+100*'/'+'   MEDIUM Severity findings   '+100*'\\')
        print_findings(medium_findings, log_type)

    all_findings = high_findings + medium_findings

    # Number of clusters in labels, ignoring noise if present.
    n_noise = list(labels).count(-1)

    logging.info('\nEstimated number of clusters: %d' % len(set(labels)))
    logging.info('Estimated number of outliers/anomalous points: %d' % n_noise)
    logging.info('DBSCAN Silhouette Coefficient: %0.3f' % sklearn.metrics.silhouette_score(dataframe, labels))
    logging.info('{} log lines detected as containing potential malicious behaviour traces'.format(list(labels).count(-1)))
    logging.info('Number of log lines by cluster:{}'.format(find_elements_by_cluster(labels)))
    logging.info('\nTotal number of log lines:{}'.format(len(data)))
    if len(minority_clusters)>0:
        logging.info('{} Minority clusters found'.format(len(minority_clusters)))
    else:
        logging.info('No minority clusters found.')
    
    #where to save the plot
    #save_plot_at ='./REPORTS/scan_plot_{}'.format(log_file.split('/')[-1].replace('.','_'))
    
    # plot findings and save the plot if save_plot_at is defined
    #plot_findings(dataframe,labels,save_plot_at)
    

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
            updated_finding = get_llm_insights([finding])

            raw_ai_advice=updated_finding[0]['ai_advice']

            try:
                json_ai_advice=json.loads(raw_ai_advice.replace('\\','').replace("'","\'"))

            except:
                logging.info('> JSON parsing issue encountred')
                logging.info(raw_ai_advice)
                data_is_ok=False
    
            if data_is_ok==True:
                updated_finding[0]['ai_advice'] = json_ai_advice['details']

                if json_ai_advice['potential_attack_attempt']==False:
                    updated_finding[0]['severity'] = 'low'
                else:
                    updated_finding[0]['severity']= json_ai_advice['severity']


                updated_finding[0]['cve']= json_ai_advice['CVE']
                updated_finding[0]['recommendation']= json_ai_advice['recommendation']
                updated_finding[0]['owasp']= json_ai_advice['owasp']
                
    
        if sync_app==True and data_is_ok:
            submit_to_app(hostname,updated_finding,log_file,log_type,config['LLM']['model'])
            
    # More details to be added to http return json
    return 'Success'