# About: Use unsupervised learning to detect intrusion/suspicious activities in http logs
# Author: walid.daboubi@gmail.com
# Version: 3.0 - 2022/12/25

import argparse
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn import metrics
from sklearn.cluster import DBSCAN
from io import StringIO

from utilities import *

parser = argparse.ArgumentParser()
parser.add_argument('-l', '--log_file', help = 'The raw http log file', required = True)
parser.add_argument('-t', '--log_type', help = 'apache or nginx', required = True)
parser.add_argument('-e', '--eps', help='Max distance between two points. The default value is 500', required=False)
parser.add_argument('-s', '--min_samples', help='Minimum number of points with the same cluster. The default value is 2', required=False)
parser.add_argument('-j', '--log_lines_limit', help='The maximum number of log lines of consider. The default value is 5000', required=False)
parser.add_argument('-v', '--show_plots', help='Show plots',  action='store_true')


def plot_informative(x,y,z):
    # This is just an informational plot to give the user an idea about how outliers can be detected
    # 2D informational plot
    print('Plotting an informative 2 dimensional visualisation')
    plt.plot(x, y, 'ko')
    plt.title("A visualisation of 2 selected  features")
    plt.show()
    # 3D informational plot
    fig = plt.figure(figsize=(10, 7))
    ax = plt.axes(projection="3d")
    # Creating plot
    print('Plotting an informative 2 dimensional visualisation')
    ax.scatter3D(x, y, z, color="black")
    plt.title("A visualisation of 3 selected  features")
    # show plot
    plt.show()


def main():

    # Get parameters
    args = vars(parser.parse_args())

    # Encode raw data file and save encoded data
    print('> Webhawk 2.0')
    print("Encoding data..")
    _,data_str = construct_enconded_data_file(encode_log_file(args['log_file'],args['log_type']),False)

    LOG_SIZE_LIMIT = int(args['log_lines_limit']) if args['log_lines_limit'] is not None else 5000
    EPS = float(args['eps']) if args['eps'] is not None else 500
    MIN_SAMPLES = int(args['min_samples']) if args['min_samples'] is not None else 2
    SHOW_PLOTS = args['show_plots']


    # Get the raw log lines
    csvStringIO = StringIO(data_str)
    data = pd.read_csv(csvStringIO, sep=",").head(LOG_SIZE_LIMIT)


    # convert to a dataframe
    # features:length,params_number,return_code,size,upper_cases,lower_cases,special_chars,url_depth
    dataframe = data.to_numpy()[:,list(range(0,8))]

    if SHOW_PLOTS:
        print('Plotting size, special_chars and url_depth')
        plot_informative(data['size'], data['special_chars'], data['url_depth'])

    print('Starting detection..')
    # Use dbscan for clustering
    dbscan_model = DBSCAN(eps=EPS, min_samples=MIN_SAMPLES).fit(dataframe)
    core_samples_mask = np.zeros_like(dbscan_model.labels_, dtype=bool)
    core_samples_mask[dbscan_model.core_sample_indices_] = True
    labels = dbscan_model.labels_

    # Find the noise (outliers) lines in the log
    log_line_number = 0
    for label in labels:
        if label == -1:
            print('\n\t/!\ Webhawk - Possible anomalous behaviour detected in line:{}'.format(log_line_number))
            print('\t{}'.format(data['log_line'][log_line_number]))
        log_line_number += 1

    # Number of clusters in labels, ignoring noise if present.
    n_clusters = len(set(labels))  #- (1 if -1 in labels else 0)
    n_noise = list(labels).count(-1)

    print("\nEstimated number of clusters: %d" % n_clusters)
    print("Estimated number of outliers/noise points: %d" % n_noise)
    print("DBSCAN Silhouette Coefficient: %0.3f" % metrics.silhouette_score(dataframe, labels))
    print('{} log lines detected as containing potential malicious behaviour traces'.format(list(labels).count(-1)))

    if SHOW_PLOTS:
        # Black removed and is used for noise instead.
        unique_labels = set(labels)
        colors = [plt.cm.Spectral(each) for each in np.linspace(0, 1, len(unique_labels))]
        # Plot clusters and outliers
        for unique_label, col in zip(unique_labels, colors):
            if unique_label == -1:
                # Black used for noise.
                col = [0, 0, 0, 1]
            class_member_mask = labels == unique_label
            xy = dataframe[class_member_mask & core_samples_mask]
            # Plot detected clusters
            plt.plot(xy[:, 0], xy[:, 1],"o",markerfacecolor=tuple(col),markeredgecolor="k",markersize=14,)
            xy = dataframe[class_member_mask & ~core_samples_mask]
            # Plot outliers
            plt.plot(xy[:, 0],xy[:, 1],"o",markerfacecolor=tuple(col),markeredgecolor="k",markersize=6,)
        plt.title("Estimated number of clusters: %d" % n_clusters)
        plt.show()

if __name__ == "__main__":
    main()
