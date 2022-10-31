import pickle

import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score,confusion_matrix,classification_report
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split
data = pd.read_csv('FP_MAIN.csv')
data = data.fillna('0')

X = data[['ARP','LLC','EAPOL','IP','ICMP','ICMP6','TCP','UDP','TCP_w_size','HTTP','HTTPS','DHCP','BOOTP','SSDP','MDNS','DNS','NTP','IP_padding','IP_add_count','IP_ralert','Portcl_src','Portcl_dst','Pck_size','Pck_rawdata','payload_l','Entropy','MAC']]
y = data[['Label']]
# 分割训练集和测试集
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
X_train=X_train[['ARP','LLC','EAPOL','IP','ICMP','ICMP6','TCP','UDP','TCP_w_size','HTTP','HTTPS','DHCP','BOOTP','SSDP','MDNS','DNS','NTP','IP_padding','IP_add_count','IP_ralert','Portcl_src','Portcl_dst','Pck_size','Pck_rawdata','payload_l','Entropy']]
print("Train set size, Test set size:", X_train.shape, y_train.shape, X_test.shape, y_test.shape)

def get_result(pred):
    f = open('Result-RandomForest.txt', 'w')
    f.write('CLASS:' + '\n')
    for p in pred:
        f.write(str(p) + '\n')

def get_result_new(pred,mac_list):
    for p,m in zip(pred,mac_list):
        print(f"mac:  {m}  device_type:{p}")

# 随机森林分类算法
from sklearn.ensemble import RandomForestClassifier
rfc = RandomForestClassifier()
rfc.fit(X_train, y_train)

with open('rfc.pkl', 'wb') as f:
    pickle.dump(rfc, f)

mac_list=X_test['MAC']
X_test=X_test[['ARP','LLC','EAPOL','IP','ICMP','ICMP6','TCP','UDP','TCP_w_size','HTTP','HTTPS','DHCP','BOOTP','SSDP','MDNS','DNS','NTP','IP_padding','IP_add_count','IP_ralert','Portcl_src','Portcl_dst','Pck_size','Pck_rawdata','payload_l','Entropy']]
y_predict = rfc.predict(X_test)

get_result(y_predict)
get_result_new(y_predict,mac_list)
print('随机森林准确率', accuracy_score(y_test, y_predict))
print('随机森林精确率', precision_score(y_test, y_predict, average='macro'))
print('随机森林召回率', recall_score(y_test, y_predict, average='macro'))
print('F1', f1_score(y_test, y_predict, average='macro'))
