import device
import requests
import os

path = os.path.dirname(os.path.realpath(__file__))
def get_image(value):
    if int(value) == 1:
        return os.path.join(path,"img/lighton.png")
    else:
        return os.path.join(path,"img/lightoff.png")

light = device.Device("Virtual Light", "img/lightoff.png", "http://localhost:8080/data", .25)
light.add_timeseries("/lights/light0/on", "State")
light.adjust_image("/lights/light0/on", get_image)
light.add_timeseries("/lights/light0/bri", "Brightness")
light.finish()

def run():
    device.main()

if __name__ == '__main__':
    device.main()
