# Webhawk/Catch 2.0
# About: Use unsupervised learning to detect intrusion/suspicious activities in http logs
# Author: walid.daboubi@gmail.com
# Reviewed: 2023/08/06 - Flight Zurich/Las Vegas


import io
import os
import kneed
import argparse
import pyfiglet
import termcolor
import urllib3
import requests
import numpy as np
import pandas as pd
import webbrowser
import sklearn.cluster
import sklearn.neighbors
import sklearn.preprocessing
import sklearn.decomposition
import matplotlib.pyplot as plt
from rich import print as rich_print


from utilities import *

def get_data(log_file, log_content, log_type, log_size_limit, features, encoding_type):
    """
    Converts a log file to a dataframe

    Parameters:
    log_file (str): The file which contains the logs
    log_content (str): The content of the logs - when used log_file will be ignored 
    log_type (str): The type of logs 
    log_size_limit (int): Used to limit the number of lines to get from the log file 
    features (str): A comma separated list of features
    encoding_type (str): label_encoding or fraction encoding
    

    Returns:
    str: A data frame 
    """
    if log_type == 'os_processes':
        data = parse_process_file(log_file)
        data = pd.DataFrame.from_records(data)
        data = data.drop_duplicates(subset=['PID'], keep='last')
        data = data.set_index('PID')
        numerical_cols = list(data._get_numeric_data().columns)
        data = data[numerical_cols]
        data = data.drop(['PGRP', 'PPID', 'UID'], axis=1)
    else:
        try:
            if log_content==None:
                with open(log_file, 'r') as file:
                    log_content = io.StringIO(file.read())
            else:
                log_content = io.StringIO(log_content)
            encoded_logs = encode_logs(log_content, log_type,encoding_type)
        except Exception as e:
            logging.info('Something went wrong encoding data.')
            sys.exit(1)
        try:
            _,data_str = construct_enconded_data_file(encoded_logs, False)
        except:
            logging.info('Something went wrong constructing data')
            sys.exit(1)
        # Get the raw log lines
        csvStringIO = io.StringIO(data_str)
        data = pd.read_csv(csvStringIO, sep=',').head(log_size_limit)
        data = data[features]
    return data


# This function makes two informative plots
def plot_data(data,title):
    """
    Makes informative plots 

    Parameters:
    data (list): The file which contains the logs
    title (str): Title of the plot 
    
    Returns:
    None
    """
    if len(data) == 2:
        # 2D informational plot
        logging.info('{} Plotting an informative 2 dimensional visualisation'.format(' '*4))
        fig = plt.figure()
        plt.plot(
            data[0],
            data[1],
            'ko')
        plt.title(title)
    if len(data) == 3:
        # 3D informational plot
        fig = plt.figure()
        ax = plt.axes(projection='3d')
        logging.info('{}Plotting an informative 3 dimensional visualisation'.format(' '*4))
        ax.scatter3D(data[0], data[1], data[2], color='black')
        plt.title(title)
    plt.show()


# This function returnt the number of elements by cluster (including the outliers 'cluster')
def find_elements_by_cluster(labels):
    elements_by_cluster={}
    for label in set(labels):
        elements_by_cluster[label]=np.count_nonzero(labels == label)
    elements_by_cluster={k: v for k, v in sorted(elements_by_cluster.items(), key=lambda item: item[1])}
    return elements_by_cluster


# This function return a list a findings
def catch(labels, data, label, log_type):
    log_line_number = 0
    if label == -1:
        severity = 'high'
    else:
        severity = 'medium'
    findings = []
    for point_label in labels:
        # Adding the anomalous points to the findings
        if point_label == label:
            if not log_type == 'os_processes':
                finding = {
                    'log_line_number':log_line_number,
                    'log_line':data['log_line'][log_line_number],
                    'severity':severity
                }
            else:
                pid = int(data.iloc[[log_line_number]].index.values[0])
                finding_line = data.iloc[[log_line_number]].values[0]
                column_names = data.columns.to_list()
                process_details = get_process_details(pid)
                finding = {
                    'pid': pid,
                    'log_line':list(zip(column_names, finding_line)),
                    'severity':severity,
                    'process_details': process_details
                }
            findings.append(finding)
        log_line_number += 1
    return findings


# This function prints the finding to the terminal
def print_findings(findings, log_type):
    for finding in findings:
        if not log_type == 'os_processes':
            logging.info('\n\t Webhawk {} - Possible anomalous behaviour detected at line:{}'.format(finding['severity'], finding['log_line_number']))
        else:
            logging.info('\n\t Webhawk {} - Possible anomalous behaviour detected at line:{}'.format(finding['severity'], finding['pid']))
        logging.info('\t{}'.format(finding['log_line']))


# This function plots the finding
def plot_findings(dataframe, labels,save_at):
    # Plot finddings
    unique_labels = set(labels)
    colors = [plt.cm.Spectral(each) for each in np.linspace(1, 0, len(unique_labels))]
    outliers_count = 0
    fig = plt.figure()
    for index, row in dataframe.iterrows():
        label = labels[index]
        # Plot outliers
        if label == -1:
            marker = 'x'
            markersize = 10
            markeredgecolor = 'r'
            outliers_count+=1
        # Plot other (minority cluster points)
        else:
            marker = 'o'
            markersize = 6
            markeredgecolor = 'black'
        plt.plot(
            row['pc_1'],
            row['pc_2'],
            marker,
            markerfacecolor=tuple(plt.cm.Spectral(np.linspace(label, 1, 1))[0]),
            markeredgecolor=markeredgecolor,
            markersize=markersize,)
    plt.title('Webhawk/Catch - {} Possible attack traces detected'.format(outliers_count))
    if save_at != None:
        plt.savefig(save_at)
    plt.show()


# This function find the maximum curvature point among the sorted neighbors distance plot
def find_max_curvature_point(dataframe, plot):
    # Finding the nearest neighbors
    neighbors = sklearn.neighbors.NearestNeighbors(n_neighbors=2)
    nbrs = neighbors.fit(dataframe)
    distances, indices = nbrs.kneighbors(dataframe)
    # Sorting the nearest neighbors distance
    sorted_idx = distances[:, 1].argsort()
    distances = distances[sorted_idx]
    indices = indices[sorted_idx]
    # Finding the maximum curvature point
    kl = kneed.KneeLocator(distances[:,1], indices[:,1], curve="convex",S=10.0)
    # Make plot if required
    if plot:
        plt.title('Sorted distance to nearest neighbors and max curvature')
        plt.plot(distances[:,1])
        plt.axhline(
            kl.knee,
            0,
            1,
            label="max curve",
            color='black',
            linestyle='--'
            )
        plt.show()
    return kl.knee


# This function optimize Epsilon to get the best BDSCAN silouhette Coefficient
def optimize_silouhette_coefficient(max_curve, dataframe, lambda_value):
    current_eps = lambda_value
    best_silouhette = 0
    best_eps_for_silouhette = None
    while current_eps <= 1.5 * max_curve:
        dbscan = sklearn.cluster.DBSCAN(eps=current_eps)
        dbscan_model = dbscan.fit(dataframe)
        labels = dbscan_model.labels_
        if len(set(dbscan_model.labels_)) > 1:
            current_silouhette = sklearn.metrics.silhouette_score(dataframe, labels)
        if current_silouhette > best_silouhette:
            best_silouhette = current_silouhette
            best_eps_for_silouhette = current_eps
        logging.debug('\nCurvature:{}'.format(current_eps))
        logging.debug('Silhouette:{}'.format(current_silouhette))
        current_eps += lambda_value
    return best_silouhette, best_eps_for_silouhette


# This function return the clusters that include a number of point <= threshold
def get_minority_clusters(elements_by_cluster,threshold):
    minority_clusters = []
    if -1 in elements_by_cluster:
        threshold += elements_by_cluster[-1]
        for key in elements_by_cluster:
            if (key!=-1 and elements_by_cluster[key]<=threshold):
                minority_clusters.append(key)
    return minority_clusters



def find_cves(findings):
    bad_chars = ['/','?','=','&','%','#']
    enriched_findings = []
    checked_candidate_strings = {}
    for finding in findings:
        # Only find CVE for the high severity findings
        if finding['severity'] == 'high':
            finding['cve'] = ''
            final_requested_url = finding['log_line'].split('"')[1].split(' ')[1]
            # Replace 'bad' chars by spaces
            for bad_char in bad_chars:
                final_requested_url=final_requested_url.replace(bad_char,' ')
            for candidate_string in final_requested_url.split(' '):
                if len(candidate_string) >= 10:
                    try:
                        if candidate_string not in checked_candidate_strings:
                            checked_candidate_strings[candidate_string] = ''
                            response = requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}'.format(candidate_string),verify=False)
                            max_cve_by_candidate_string = 10
                            if response.status_code == 200 and 'vulnerabilities' in response.json():
                                for vuln in response.json()['vulnerabilities']:
                                    # Get only the most recent CVE
                                    cve_year=int(vuln['cve']['id'].split('-')[1])
                                    if cve_year>=int(config['CVE']['year_threshold']):
                                        logging.info('{} found'.format(vuln['cve']['id']))
                                        max_cve_by_candidate_string -= 1
                                        if max_cve_by_candidate_string == 0:
                                            break
                                        finding['cve'] += vuln['cve']['id']+' '
                                        checked_candidate_strings[candidate_string]+=vuln['cve']['id']+' '
                                # Sleep to ne be blocked by services.nvd.nist.gov
                                time.sleep(10)
                        else:
                            finding['cve'] += checked_candidate_strings[candidate_string] + ' '
                    except:
                        logging.info('Something wrong getting CVE(s)')
        enriched_findings.append(finding)
    return enriched_findings


def get_llm_insights(findings):
    enriched_findings = []
    current=1
    count=len(findings)
    for finding in findings:
        logging.info('> Getting AI advice {}/{}'.format(current,count))
        current+=1
        finding['ai_advice'] = ''
        final_requested_url = finding['log_line'].split('"')[1].split(' ')[1]
        url=config['LLM']['url']
        data = {
                "model": config['LLM']['model'],
                "prompt": (
                    "{} {}".format(config['LLM']['prompt'],finding['log_line'])
                ),
                "stream": False,
        }
        response = requests.post(url, json=data)
        finding['ai_advice'] = response.json()['response']
        enriched_findings.append(finding)
    return enriched_findings

    


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--log_file', help = 'The raw log file', required = True)
    parser.add_argument('-t', '--log_type', help = 'apache, http, nginx or os_processes', required = True)
    parser.add_argument('-e', '--eps', help='DBSCAN Epsilon value (Max distance between two points)', required=False)
    parser.add_argument('-s', '--min_samples', help='Minimum number of points with the same cluster. The default value is 2', required=False)
    parser.add_argument('-j', '--log_lines_limit', help='The maximum number of log lines of consider', required=False)
    parser.add_argument('-y', '--opt_lamda', help = 'Optimization lambda step', required = False)
    parser.add_argument('-m', '--minority_threshold', help = 'Minority clusters threshold', required = False)
    parser.add_argument('-p', '--show_plots', help='Show informative plots',  action='store_true')
    parser.add_argument('-o', '--standardize_data', help='Standardize feature values',  action='store_true')
    parser.add_argument('-r', '--report', help='Create a HTML report', action='store_true')
    parser.add_argument('-z', '--opt_silouhette', help='Optimize DBSCAN silouhette', action='store_true')
    parser.add_argument('-b', '--debug', help = 'Activate debug logging', action='store_true')
    parser.add_argument('-c', '--label_encoding', help = 'Use label encoding instead of frequeny encoding to encode categorical features', action='store_true')
    parser.add_argument('-v', '--find_cves', help = 'Find the CVE(s) that are related to the attack traces', action='store_true')
    parser.add_argument('-a', '--get_ai_advice', help = 'Get AI advice on the detection', action='store_true')
    parser.add_argument('-q', '--quick_scan', help = 'Only most critical detection (no minority clusters)', action='store_true')
    urllib3.disable_warnings()

    # Get parameters
    args = vars(parser.parse_args())


    logging_level = logging.DEBUG if args['debug'] else logging.INFO
    logging.basicConfig(level=logging_level)


    LOG_LINES_LIMIT = int(args['log_lines_limit']) if args['log_lines_limit'] is not None else 1000000
    LAMBDA = float(args['opt_lamda']) if args['opt_lamda'] is not None else 0.01
    THRESHOLD = int(args['minority_threshold']) if args['minority_threshold'] else 5

    encoding_type = 'label_encoding' if args['label_encoding'] == True else 'fraction_encoding'

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


    print('\n')
    #print((termcolor.colored(pyfiglet.figlet_format('Webhawk 3.0',font = 'univers', width=600), color='red')))

    

    rich_print("[bold red]>>> Webhawk v3.0[/bold red]")
    rich_print("[bold red]>>> Attack detection using machine learning[/bold red]")

    rich_print("[dim]Author: walid.daboubi@gmail.com[/dim]")
    print('\n')


    logging.info('\n> Webhawk Catch 2.0')
    logging.info('{}The input log file is {}'.format(' '*4,args['log_type']))
    logging.info('{}Log format is set to {}'.format(' '*4,args['log_type']))
    logging.info('{}Demo plotting is set to {}'.format(' '*4,args['show_plots']))
    logging.info('{}Features standarization is set to {}'.format(' '*4,args['standardize_data']))

    # Get data
    logging.info('\n> Data reading started')


    data = get_data(
        args['log_file'],
        None, # No log_content is required as the file path is provided 
        args['log_type'],
        LOG_LINES_LIMIT,
        FEATURES,
        encoding_type)

    # convert to a dataframe
    if args['log_type'] != 'os_processes':
        dataframe = data.to_numpy()[:,list(range(0,len(FEATURES)-1))]
    else:
        dataframe = data

    # Standarize data
    if args['standardize_data']:
        dataframe = sklearn.preprocessing.StandardScaler().fit_transform(dataframe)

    # Show informative data plots
    if args['show_plots']:
        logging.info('\n> Informative plotting started')
        if args['log_type'] != 'os_processes':
            plot_data([data['http_query'],data['url_depth']],'Informative plot of http_query and url_depth')
            plot_data([data['http_query'],data['url_depth'],data['return_code']],'Informative plot of http_query, url_depth and return_code')
        else:
            plot_data([data['%CPU'],data['POWER']],'Plotting %CPU and POWER')
            plot_data([data['%CPU'],data['POWER'],data['CYCLES']],'Plotting %CPU, POWER and CYCLES')


    # Dimensiality reduction to 2d using PCA
    pca = sklearn.decomposition.PCA(n_components=2)
    principal_components_df = pca.fit_transform(dataframe)
    dataframe = pd.DataFrame(
        data = principal_components_df,
        columns = ['pc_1', 'pc_2'])

    # Display and plot data after applying PCA
    plot_data([dataframe['pc_1'],dataframe['pc_2']],'Data after dimensiality reduction using PCA')


    # Getting or setting epsilon
    if args['eps'] == None:
        logging.info('\n> No Epsilon input. Finding the max sorted neighbors curvature point and use it as Epsilon')
        automatic_max_curve_point = find_max_curvature_point(dataframe, args['show_plots'])
        selected_eps = automatic_max_curve_point
        logging.info('{}{}'.format(4*' ',automatic_max_curve_point))
    else:
        selected_eps=float(args['eps'])

    if args['opt_silouhette']:
        logging.info('\n> Optimizing Epsilon to get the best BDSCAN Silhouette Coefficient')
        best_silouhette, best_eps_for_silouhette = optimize_silouhette_coefficient(selected_eps, dataframe, LAMBDA)
        logging.info('{}{}'.format(4*' ', best_eps_for_silouhette))
        selected_eps = best_eps_for_silouhette

    logging.info('{}The value {} will be used as final DBSCAN Epsilon'.format(4*' ', selected_eps))

    logging.info('\n> Starting detection..')
    # Use dbscan for clustering and train the model

    if args['eps'] == None and args['min_samples'] == None:
        dbscan = sklearn.cluster.DBSCAN(eps=selected_eps)
    elif args['eps'] == None:
        dbscan = sklearn.cluster.DBSCAN(eps=selected_eps, min_samples=int(args['min_samples']))
    elif args['min_samples'] == None:
        dbscan = sklearn.cluster.DBSCAN(eps=selected_eps)
    else:
        dbscan = sklearn.cluster.DBSCAN(eps=selected_eps, min_samples=int(args['min_samples']))
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
    if args['quick_scan']==True:
        minority_clusters=[]
    else:
        minority_clusters = get_minority_clusters(elements_by_cluster,THRESHOLD)
        

    # Outliers are considred as high severity findings

    high_findings = catch(labels,data,-1, args['log_type'])
    if len(high_findings)>0:
        logging.info ('\n\n\n\n    '+100*'/'+'   HIGH Severity findings   '+100*'\\')
        print_findings(high_findings, args['log_type'])

    # Points belonging to minority clusters are considred as medium severity findings
    medium_findings=[]
    for label in minority_clusters:
        if label != -1:
            medium_findings += catch(labels,data,label, args['log_type'])

    if len(medium_findings) > 0:
        logging.info ('\n\n\n\n    '+100*'/'+'   MEDIUM Severity findings   '+100*'\\')
        print_findings(medium_findings, args['log_type'])

    all_findings = high_findings + medium_findings



    # Number of clusters in labels, ignoring noise if present.
    n_noise = list(labels).count(-1)

    logging.info('\nEstimated number of clusters: %d' % len(set(labels)))
    logging.info('Estimated number of outliers/anomalous points: %d' % n_noise)
    logging.info('DBSCAN Silhouette Coefficient: %0.3f' % sklearn.metrics.silhouette_score(dataframe, labels))
    logging.info('{} log lines detected as containing potential malicious behaviour traces'.format(list(labels).count(-1)))
    #logging.info('Number of log lines by cluster:{}'.format(find_elements_by_cluster(labels)))
    logging.info('\nTotal number of log lines:{}'.format(len(data)))
    if len(minority_clusters)>0:
        logging.info('The minority clusters are:{}'.format(minority_clusters))
    else:
        logging.info('No minority clusters found, or you selected a quick scan')

    #where to save the plot
    save_plot_at ='./REPORTS/scan_plot_{}'.format(args['log_file'].split('/')[-1].replace('.','_'))

    # plot findings and save the plot if save_plot_at is defined
    plot_findings(dataframe,labels,save_plot_at)

    if args['find_cves'] == True:
        logging.info('> Finding CVEs started')
        all_findings = find_cves(all_findings)
    if args['get_ai_advice'] == True:
        logging.info('> Getting AI advice')
        all_findings = get_llm_insights(all_findings)

    # Generate a HTML report if requested
    if args['report']:
        #find_cves(all_findings)
        report_file=gen_report(
            all_findings,args['log_file'],
            args['log_type'],
            config['LLM']['model']
            )
        webbrowser.open('file://{}/{}'.format(os.getcwd(),report_file))


if __name__ == '__main__':
    main()
