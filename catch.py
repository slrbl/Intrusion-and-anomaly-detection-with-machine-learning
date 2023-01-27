# About: Use unsupervised learning to detect intrusion/suspicious activities in http logs
# Author: walid.daboubi@gmail.com

import io
import kneed
import argparse
import pyfiglet
import termcolor
import matplotlib
import numpy as np
import pandas as pd
import sklearn.cluster
import sklearn.neighbors
import sklearn.preprocessing
import sklearn.decomposition
import matplotlib.pyplot as plt
import logging

from utilities import *


parser = argparse.ArgumentParser()
parser.add_argument('-b', '--debug', help = 'Activate debug logging', action='store_true')
parser.add_argument('-l', '--log_file', help = 'The raw http log file', required = True)
parser.add_argument('-t', '--log_type', help = 'apache or nginx', required = True)
parser.add_argument('-e', '--eps', help='DBSCAN Epsilon value (Max distance between two points)', required=False)
parser.add_argument('-s', '--min_samples', help='Minimum number of points with the same cluster. The default value is 2', required=False)
parser.add_argument('-j', '--log_lines_limit', help='The maximum number of log lines of consider', required=False)
parser.add_argument('-p', '--show_plots', help='Show informative plots',  action='store_true')
parser.add_argument('-o', '--standarize_data', help='Smooth feature values',  action='store_true')
parser.add_argument('-r', '--report', help='Create a HTML report', action='store_true')
parser.add_argument('-z', '--opt_silouhette', help='Optimize DBSCAN silouhette', action='store_true')
parser.add_argument('-y', '--opt_lamda', help = 'Optimization lambda step', required = False)



# This function makes two informative plots
def plot_informative(x, y, z):
    # 2D informational plot
    logging.info('{}Plotting an informative 2 dimensional visualisation'.format(' '*4))
    plt.plot(
        x,
        y,
        'ko')
    plt.title('A informative visualisation of 2 selected  features')
    plt.show()


    # 3D informational plot
    fig = plt.figure(figsize=(10, 7))
    ax = plt.axes(projection='3d')
    logging.info('{}Plotting an informative 3 dimensional visualisation'.format(' '*4))
    ax.scatter3D(x, y, z, color='black')
    plt.title('An informative visualisation of 3 selected  features')
    plt.show()

# This function returns takes as input a log_file and returns a dataframe
def get_data(log_file, log_type, log_size_limit, FEATURES):
    try:
        encoded_logs = encode_log_file(log_file, log_type)
    except:
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
    data = data[FEATURES]
    return data

# This function returnt the number of elements by cluster (including the outliers 'cluster')
def find_elements_by_cluster(labels):
    elements_by_cluster={}
    for label in set(labels):
        elements_by_cluster[label]=np.count_nonzero(labels == label)
    elements_by_cluster={k: v for k, v in sorted(elements_by_cluster.items(), key=lambda item: item[1])}
    return elements_by_cluster

# This function return a list a findings
def catch(labels, data, label):
    log_line_number = 0
    if label == -1:
        severity = 'high'
    else:
        severity = 'medium'
    findings = []
    for point_label in labels:
        # Adding the anomalous points to the findings
        if point_label == label:
            finding = {
                'log_line_number':log_line_number,
                'log_line':data['log_line'][log_line_number],
                'severity':severity
            }
            findings.append(finding)
        log_line_number += 1
    return findings

# This function prints the finding to the terminal
def print_findings(findings):
    for finding in findings:
        logging.info('\n\t/!\ Webhawk {} - Possible anomalous behaviour detected at line:{}'.format(finding['severity'], finding['log_line_number']))
        logging.info('\t{}'.format(finding['log_line']))

# This function plots the finding
def plot_findings(dataframe, labels):
    # Plot finddings
    unique_labels = set(labels)
    colors = [plt.cm.Spectral(each) for each in np.linspace(1, 0, len(unique_labels))]
    outliers_count = 0
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
            color = plt.cm.Spectral(np.linspace(label, 1, 1))[0]
            marker = 'o'
            markersize = 6
            markeredgecolor = 'black'
        plt.plot(
            row['pc_1'],
            row['pc_2'],
            marker,
            markerfacecolor=tuple(color),
            markeredgecolor=markeredgecolor,
            markersize=markersize,)
    plt.title('Webhawk/Catch - {} Possible attacks detected'.format(outliers_count))
    plt.show()

# This function find the maximum curvature point among the sorted neighbors distance plot
def find_max_curvature_point(dataframe, plot):
    # Finding the nearest neighbors
    neighbors = sklearn.neighbors.NearestNeighbors(n_neighbors=2)
    nbrs = neighbors.fit(dataframe)
    distances, indices = nbrs.kneighbors(dataframe)
    # Sorting the nearest neighbors distance
    distances = np.sort(distances, axis=0)
    # Finding the maximum curvature point
    kl = kneed.KneeLocator(distances[:,1], indices[:,1], curve="convex")
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


def main():

    # Get parameters
    args = vars(parser.parse_args())


    logging_level = logging.DEBUG if args['debug'] else logging.INFO
    logging.basicConfig(level=logging_level)


    LOG_LINES_LIMIT = int(args['log_lines_limit']) if args['log_lines_limit'] is not None else 1000000
    LAMBDA = float(args['opt_lamda']) if args['opt_lamda'] is not None else 0.01
    FEATURES = [
        'params_number',
        #'size', # Stopped using size because it make a lot of false positive detections
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
    print((termcolor.colored(pyfiglet.figlet_format('Webhawk / Catch 2.0',font = 'banner3', width=600), color='red')))


    logging.info('\n> Webhawk Catch 2.0')
    logging.info('{}The input log file is {}'.format(' '*4,args['log_type']))
    logging.info('{}Log format is set to {}'.format(' '*4,args['log_type']))
    logging.info('{}Demo plotting is set to {}'.format(' '*4,args['show_plots']))
    logging.info('{}Features standarization is set to {}'.format(' '*4,args['standarize_data']))

    # Get data
    logging.info('\n> Data reading started')


    data = get_data(
        args['log_file'],
        args['log_type'],
        LOG_LINES_LIMIT,
        FEATURES)

    # convert to a dataframe
    dataframe = data.to_numpy()[:,list(range(0,len(FEATURES)-1))]

    # Standarize data
    if args['standarize_data']:
        dataframe = sklearn.preprocessing.StandardScaler().fit_transform(dataframe)

    # Show informative data plots
    if args['show_plots']:
        logging.info('\n> Informative plotting started')
        logging.info('{}Plotting http_query, url_depth and return_code'.format(' '*4))
        plot_informative(
            data['http_query'],
            data['url_depth'],
            data['return_code'])

    # Dimensiality reduction to 2d using PCA
    pca = sklearn.decomposition.PCA(n_components=2)
    principal_components_df = pca.fit_transform(dataframe)
    dataframe = pd.DataFrame(
        data = principal_components_df,
        columns = ['pc_1', 'pc_2'])

    # Getting or setting epsilon
    if args['eps'] == None:
        logging.info('\n> No Epsilon input. Finding the max sorted neighbors curvature point and use it as Epsilon')
        automatic_max_curve_point = find_max_curvature_point(dataframe, args['show_plots'])
        selected_eps = automatic_max_curve_point
        logging.info('{}{}'.format(4*' ',automatic_max_curve_point))

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

    # Get top N minority clusters
    N = int(number_of_clusters/3)

    minority_clusters = list(elements_by_cluster.keys())[:N]

    # Outliers are considred as high severity findings

    high_findings = catch(labels,data,-1)
    if len(high_findings)>0:
        logging.info ('\n\n\n\n    '+100*'/'+'   HIGH Severity findings   '+100*'\\')
        print_findings(high_findings)

    # Points belonging to minority clusters are considred as medium severity findings
    medium_findings=[]
    for label in minority_clusters:
        if label != -1:
            medium_findings += catch(labels,data,label)

    if len(medium_findings) > 0:
        logging.info ('\n\n\n\n    '+100*'/'+'   MEDIUM Severity findings   '+100*'\\')
        print_findings(medium_findings)

    all_findings = high_findings + medium_findings

    # Generate a HTML report is required
    if args['report']:
        gen_report(
            all_findings,args['log_file'],
            args['log_type'])

    # Number of clusters in labels, ignoring noise if present.
    n_noise = list(labels).count(-1)

    logging.info('\nEstimated number of clusters: %d' % len(set(labels)))
    logging.info('Estimated number of outliers/anomalous points: %d' % n_noise)
    logging.info('DBSCAN Silhouette Coefficient: %0.3f' % sklearn.metrics.silhouette_score(dataframe, labels))
    logging.info('{} log lines detected as containing potential malicious behaviour traces'.format(list(labels).count(-1)))
    logging.info('Number of log lines by cluster:{}'.format(find_elements_by_cluster(labels)))
    logging.info('\nTotal number of log lines:{}'.format(len(data)))
    logging.info('The top {} minority clusters are:{}'.format(N,minority_clusters))

    if args['show_plots']:
        plot_findings(dataframe,labels)

if __name__ == '__main__':
    main()
