import device
import requests
import os

path = os.path.dirname(os.path.realpath(__file__))
button = device.Device("Virtual Button", "img/off_button.jpg", "http://localhost:8080/data", .25)
button.add_timeseries("/controllers/0/on", "State")
button.finish()

def run():
    device.main()

if __name__ == '__main__':
    device.main()
