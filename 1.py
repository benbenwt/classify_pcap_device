import pandas as pd

f = pd.read_csv('FP_MAIN.csv')

f.replace('Smart Things','0',inplace=True)
f.replace('Amazon Echo','1',inplace=True)
f.replace('Netatmo Welcome','2',inplace=True)
f.replace('TP-Link Day Night Cloud camera','3',inplace=True)
f.replace('Samsung SmartCam','4',inplace=True)
f.replace('Dropcam','5',inplace=True)
f.replace('Insteon Camera','6',inplace=True)
f.replace('unknown maybe cam','7',inplace=True)
f.replace('Withings Smart Baby Monitor','8',inplace=True)
f.replace('Belkin Wemo switch','9',inplace=True)
f.replace('TP-Link Smart plug','10',inplace=True)
f.replace('iHome','11',inplace=True)
f.replace('Belkin wemo motion sensor','12',inplace=True)
f.replace('NEST Protect smoke alarm','13',inplace=True)
f.replace('Netatmo weather station','14',inplace=True)
f.replace('Withings Smart scale','15',inplace=True)
f.replace('Blipcare Blood Pressure meter','16',inplace=True)
f.replace('Withings Aura smart sleep sensor','17',inplace=True)
f.replace('Light Bulbs LiFX Smart Bulb','18',inplace=True)
f.replace('Triby Speaker','19',inplace=True)
f.replace('PIX-STAR Photo-frame','20',inplace=True)
f.replace('HP Printer','21',inplace=True)
f.replace('Samsung Galaxy Tab','22',inplace=True)
f.replace('Nest Dropcam','23',inplace=True)
f.replace('Android Phone','24',inplace=True)
f.replace('Laptop','25',inplace=True)
f.replace('MacBook','26',inplace=True)
# f.replace('Android Phone 2','27',inplace=True)
f.replace('IPhone','27',inplace=True)
f.replace('MacBook/Iphone','28',inplace=True)
f.replace('TPLink Router Bridge LAN (Gateway)','29',inplace=True)



f.to_csv('FP_main111.csv')