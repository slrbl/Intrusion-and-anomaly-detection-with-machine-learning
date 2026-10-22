# Webhawk/Catch 2.0
# About: Use unsupervised learning to detect intrusion/suspicious activities in http logs
# Author: walid.daboubi@gmail.com
# Reviewed: 2023/08/06 - Flight Zurich/Las Vegas


import io
import os
import kneed
import argparse
import socket
import pyfiglet
import termcolor
import urllib3
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
from enrich import find_cves, get_llm_insights

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
                logging.info('Logs have successfully been loaded from client..')
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




import os
from urllib.parse import urlparse, parse_qs

def extract_filenames_from_url(http_url: str, param_name='file') -> list:
    """
    Extracts file names from both the path and query parameters of an HTTP URL.

    Args:
        http_url (str): The full HTTP URL.
        param_name (str): The query parameter name to extract (default is 'file').

    Returns:
        list: A list of file names found in the URL.
    """
    parsed = urlparse(http_url)

    filenames = []

    # Extract filename from the path, if the last segment looks like a file
    path_basename = os.path.basename(parsed.path)
    if '.' in path_basename:  # crude check for a file extension
        filenames.append(path_basename)

    # Extract file(s) from query string
    query_params = parse_qs(parsed.query)
    filenames += query_params.get(param_name, [])

    return filenames


HTTP_FEATURES = [
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


def detect(
    log_file,
    log_content,
    log_type,
    log_lines_limit=1000000,
    encoding_type='fraction_encoding',
    standardize=False,
    eps=None,
    min_samples=None,
    opt_silhouette=False,
    opt_lambda=0.01,
    minority_threshold=5,
    quick_scan=False,
    show_plots=False,
    plot_after_pca=False,
):
    """
    Cluster log lines and return high and medium findings.

    Returns None when DBSCAN finds a single cluster and there is nothing to report.
    """
    logging.info('\n> Data reading started')
    data = get_data(
        log_file,
        log_content,
        log_type,
        log_lines_limit,
        HTTP_FEATURES,
        encoding_type,
    )

    if log_type != 'os_processes':
        dataframe = data.to_numpy()[:, list(range(0, len(HTTP_FEATURES) - 1))]
    else:
        dataframe = data

    if standardize:
        dataframe = sklearn.preprocessing.StandardScaler().fit_transform(dataframe)

    if show_plots:
        logging.info('\n> Informative plotting started')
        if log_type != 'os_processes':
            plot_data([data['http_query'], data['url_depth']], 'Informative plot of http_query and url_depth')
            plot_data(
                [data['http_query'], data['url_depth'], data['return_code']],
                'Informative plot of http_query, url_depth and return_code',
            )
        else:
            plot_data([data['%CPU'], data['POWER']], 'Plotting %CPU and POWER')
            plot_data([data['%CPU'], data['POWER'], data['CYCLES']], 'Plotting %CPU, POWER and CYCLES')

    pca = sklearn.decomposition.PCA(n_components=2)
    principal_components_df = pca.fit_transform(dataframe)
    dataframe = pd.DataFrame(
        data=principal_components_df,
        columns=['pc_1', 'pc_2'],
    )

    if plot_after_pca:
        plot_data([dataframe['pc_1'], dataframe['pc_2']], 'Data after dimensiality reduction using PCA')

    if eps is None:
        logging.info('\n> No Epsilon input. Finding the max sorted neighbors curvature point and use it as Epsilon')
        selected_eps = find_max_curvature_point(dataframe, show_plots)
        logging.info('{}{}'.format(4 * ' ', selected_eps))
    else:
        selected_eps = float(eps)

    if opt_silhouette:
        logging.info('\n> Optimizing Epsilon to get the best BDSCAN Silhouette Coefficient')
        best_silouhette, best_eps_for_silouhette = optimize_silouhette_coefficient(
            selected_eps, dataframe, opt_lambda
        )
        logging.info('{}{}'.format(4 * ' ', best_eps_for_silouhette))
        selected_eps = best_eps_for_silouhette

    logging.info('{}The value {} will be used as final DBSCAN Epsilon'.format(4 * ' ', selected_eps))
    logging.info('\n> Starting detection..')

    if min_samples is None:
        dbscan = sklearn.cluster.DBSCAN(eps=selected_eps)
    else:
        dbscan = sklearn.cluster.DBSCAN(eps=selected_eps, min_samples=int(min_samples))
    dbscan_model = dbscan.fit(dataframe)

    if len(set(dbscan_model.labels_)) == 1:
        logging.info('{}Only one cluster was found using the value {} as epsilon'.format(4 * ' ', selected_eps))
        logging.info('{}Trying without epsilon'.format(4 * ' '))
        dbscan = sklearn.cluster.DBSCAN()
        dbscan_model = dbscan.fit(dataframe)
    if len(set(dbscan_model.labels_)) == 1:
        logging.info('{}Only one cluster was found without an epsilon value.'.format(4 * ' '))
        return None

    labels = dbscan_model.labels_
    elements_by_cluster = find_elements_by_cluster(labels)
    if quick_scan:
        minority_clusters = []
    else:
        minority_clusters = get_minority_clusters(elements_by_cluster, minority_threshold)

    high_findings = catch(labels, data, -1, log_type)
    if len(high_findings) > 0:
        logging.info('\n\n\n\n    ' + 100 * '/' + '   HIGH Severity findings   ' + 100 * '\\')
        print_findings(high_findings, log_type)

    medium_findings = []
    for label in minority_clusters:
        if label != -1:
            medium_findings += catch(labels, data, label, log_type)

    if len(medium_findings) > 0:
        logging.info('\n\n\n\n    ' + 100 * '/' + '   MEDIUM Severity findings   ' + 100 * '\\')
        print_findings(medium_findings, log_type)

    n_noise = list(labels).count(-1)
    logging.info('\nEstimated number of clusters: %d' % len(set(labels)))
    logging.info('Estimated number of outliers/anomalous points: %d' % n_noise)
    logging.info('DBSCAN Silhouette Coefficient: %0.3f' % sklearn.metrics.silhouette_score(dataframe, labels))
    logging.info('{} log lines detected as containing potential malicious behaviour traces'.format(n_noise))
    logging.info('Number of log lines by cluster:{}'.format(elements_by_cluster))
    logging.info('\nTotal number of log lines:{}'.format(len(data)))
    if len(minority_clusters) > 0:
        logging.info('{} Minority clusters found'.format(len(minority_clusters)))
    else:
        logging.info('No minority clusters found, or you selected a quick scan')

    return {
        'findings': high_findings + medium_findings,
        'dataframe': dataframe,
        'labels': labels,
    }


def main():

    get_stats('cli')

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
    parser.add_argument('-f', '--submit_to_app', help = 'Submit the finding to Webhawk app', action='store_true')
    urllib3.disable_warnings()

    # Get parameters
    args = vars(parser.parse_args())


    logging_level = logging.DEBUG if args['debug'] else logging.INFO
    logging.basicConfig(level=logging_level)


    LOG_LINES_LIMIT = int(args['log_lines_limit']) if args['log_lines_limit'] is not None else 1000000
    LAMBDA = float(args['opt_lamda']) if args['opt_lamda'] is not None else 0.01
    THRESHOLD = int(args['minority_threshold']) if args['minority_threshold'] else 5

    encoding_type = 'label_encoding' if args['label_encoding'] == True else 'fraction_encoding'

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

    result = detect(
        log_file=args['log_file'],
        log_content=None,
        log_type=args['log_type'],
        log_lines_limit=LOG_LINES_LIMIT,
        encoding_type=encoding_type,
        standardize=args['standardize_data'],
        eps=float(args['eps']) if args['eps'] is not None else None,
        min_samples=int(args['min_samples']) if args['min_samples'] is not None else None,
        opt_silhouette=args['opt_silouhette'],
        opt_lambda=LAMBDA,
        minority_threshold=THRESHOLD,
        quick_scan=args['quick_scan'],
        show_plots=args['show_plots'],
        plot_after_pca=True,
    )
    if result is None:
        sys.exit(0)

    all_findings = result['findings']

    #where to save the plot
    save_plot_at ='./REPORTS/scan_plot_{}'.format(args['log_file'].split('/')[-1].replace('.','_'))

    # plot findings and save the plot if save_plot_at is defined
    plot_findings(result['dataframe'], result['labels'], save_plot_at)

    if args['find_cves'] == True:
        logging.info('> Finding CVEs started')
        all_findings = find_cves(all_findings)
    if args['get_ai_advice'] == True:
        logging.info('> Getting AI advice started')
        all_findings = get_llm_insights(all_findings)

    # Generate a HTML report if requested
    if args['report']:
        logging.info('> Report generation')
        #find_cves(all_findings)
        report_file=gen_report(
            all_findings,args['log_file'],
            args['log_type'],
            config['LLM']['model']
            )
        webbrowser.open('file://{}/{}'.format(os.getcwd(),report_file))

    if args['submit_to_app']:

        hostname=socket.gethostname()
        logging.info('> Submission to Webhawk app')
        submit_to_app(
            hostname,
            all_findings,args['log_file'],
            args['log_type'],
            config['LLM']['model']
            )



if __name__ == '__main__':
    main()
