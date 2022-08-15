# About: Use unsupervised learning to detect intrusion/suspecious activities in http logs
# Author: walid.daboubi@gmail.com
# Version: 2.0 - 2022/08/14

from helpers import *
import matplotlib.pyplot as plt
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn import metrics
import sys


parser = argparse.ArgumentParser()
parser.add_argument('-l', '--encoded_logs_file', help = 'The file containing the encoded logs', required = True)
parser.add_argument('-e', '--eps', help = 'Max distance between two points. The default value is 500', required = False)
parser.add_argument('-s', '--min_samples', help = 'Minimum number of points with the same cluster. The default value is 2', required = False)
parser.add_argument('-j', '--log_lines_limit', help = 'The maximum number of log lines of consider. The default value is 5000', required = False)
parser.add_argument('-v', '--show_plots', help = 'Show the clustering plots',  action='store_true')


# Get parameters
args = vars(parser.parse_args())
ENCODED_LOGS_FILE = args['encoded_logs_file']
LOG_LINES_LIMIT = int(args['log_lines_limit']) if args['log_lines_limit'] != None else 5000
EPS = float(args['eps']) if args['eps'] != None else 500
MIN_SAMPLES = int(args['min_samples']) if args['min_samples'] != None else 2
SHOW_PLOTS = args['show_plots']

# Getting/preparing data
data = read_csv(ENCODED_LOGS_FILE)
# Get the raw log lines
data=data.head(LOG_LINES_LIMIT)
log_lines = data['log_line'].tolist()
# convert to a dataframe
data = data.to_numpy()[:,list(range(0,8))]

if SHOW_PLOTS == True:
    # This is just an informationl plot
    # to give the user an idea about how outliers can be detected
    x = [data[1] for data in data]
    y = [data[6] for data in data]
    # 2D informationl plot
    plt.plot(x, y, 'ko')
    plt.title("A visualisation of 2 selected  features")
    plt.show()
    z = [data[7] for data in data]
    # 3D informational plot
    fig = plt.figure(figsize = (10, 7))
    ax = plt.axes(projection ="3d")
    # Creating plot
    ax.scatter3D(x, y, z, color = "black")
    plt.title("A visualisation of 3 selected  features")
    # show plot
    plt.show()

print('Starting detection..')

dbscan_model = DBSCAN(eps=EPS, min_samples=MIN_SAMPLES).fit(data)
core_samples_mask = np.zeros_like(dbscan_model.labels_, dtype=bool)
core_samples_mask[dbscan_model.core_sample_indices_] = True
labels = dbscan_model.labels_

# Number of clusters in labels, ignoring noise if present.
n_clusters_ = len(set(labels)) #- (1 if -1 in labels else 0)
n_noise_ = list(labels).count(-1)

# Black removed and is used for noise instead.
unique_labels = set(labels)
colors = [plt.cm.Spectral(each) for each in np.linspace(0, 1, len(unique_labels))]


for k, col in zip(unique_labels, colors):
    if k == -1:
        # Black used for noise.
        col = [0, 0, 0, 1]
    class_member_mask = labels == k
    xy = data[class_member_mask & core_samples_mask]
    # Plot detected clusters
    plt.plot(xy[:, 0], xy[:, 1],"o",markerfacecolor=tuple(col),markeredgecolor="k",markersize=14,)
    xy = data[class_member_mask & ~core_samples_mask]
    # Plot outiliers
    log_line_number = 0
    outliers_count=0
    for h in class_member_mask & ~core_samples_mask:
        if h == True:
            print('\n/!\ Possible anomalous behaviour detected in line:{}'.format(log_line_number))
            print(log_lines[log_line_number])
            outliers_count += 1
        log_line_number+=1
    # Plot outliers
    plt.plot(xy[:, 0],xy[:, 1],"o",markerfacecolor=tuple(col),markeredgecolor="k",markersize=6,)

print("\nEstimated number of clusters: %d" % n_clusters_)
print("Estimated number of noise points: %d" % n_noise_)
print("Silhouette Coefficient: %0.3f" % metrics.silhouette_score(data, labels))
print('{} log lines has detected as containing potential malicious behaviour traces'.format(outliers_count))

if SHOW_PLOTS == True:
    plt.title("Estimated number of clusters: %d" % n_clusters_)
    plt.show()
