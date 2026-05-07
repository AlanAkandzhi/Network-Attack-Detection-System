from sklearn.metrics import classification_report
import numpy as np

y_true = np.random.randint(0, 2, 500)
y_pred = np.random.randint(0, 2, 500)

report = classification_report(y_true, y_pred)

print(report)