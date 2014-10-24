import device
import requests
import os

def get_image(value):
    if int(value) == 1:
        return os.path.join(path,"img/on_button.jpg")
    else:
        return os.path.join(path,"img/off_button.jpg")


path = os.path.dirname(os.path.realpath(__file__))
button = device.Device("Virtual Button", "img/off_button.jpg", "http://localhost:8080/data", .25)
button.add_timeseries("/controllers/0/on", "State")
button.adjust_image("/controllers/0/on", get_image)
button.add_actuator("/controllers/0/on_act", "On/Off", "On", "Off") # path to actuator, label, states
button.finish()

def run():
    device.main()

if __name__ == '__main__':
    device.main()
