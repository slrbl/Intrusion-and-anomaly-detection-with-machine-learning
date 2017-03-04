
import numpy as np
from sklearn import tree,linear_model
import sys

train_data_file=sys.argv[1]
test_data_file=sys.argv[2]

#train_data_file='labeled_data_train.csv'
#test_data_file='labeled_data_train.csv'

labeled_data_train = np.genfromtxt (train_data_file, delimiter=",")
data_train=labeled_data_train[:,[0,1,2]]
label_train=labeled_data_train[:,3]

labeled_data_test = np.genfromtxt (test_data_file, delimiter=",")
data_test=labeled_data_test[:,[0,1,2]]
label_test=labeled_data_test[:,3]

attack_classifier=tree.DecisionTreeClassifier()
attack_classifier=attack_classifier.fit(data_train,label_train)

# ---------------------

h = .02  # step size in the mesh

logreg = linear_model.LogisticRegression(C=1e5)

logreg.fit(data_train,label_train)

# ----------------

#print test_data

c=0
predicted_count=0.
fitted_count=0. #exactly predicted


indices=[]

for predicted in attack_classifier.predict(data_test):
	if predicted==1:
		indices.append(c)
		predicted_count+=1
		if label_test[c]==1:
			fitted_count+=1
		print predicted
		print label_test[c]
		print "-----------------"
	c+=1

print predicted_count
print fitted_count

print 100.0*(fitted_count/predicted_count)

print indices

#print attack_classifier.predict(data_test)

with open("attack_decision_tree.dot", 'w') as f:
	f = tree.export_graphviz(attack_classifier, out_file=f)
