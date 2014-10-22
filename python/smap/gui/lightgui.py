import device
import requests

"""
How many rows? -- how ever many timeseries
How many columns? -- the max number of discrete points for an actuator: at least 2

"""

def get_image(value):
    if int(value) == 1:
        return "img/lighton.png"
    else:
        return "img/lightoff.png"

light = device.Device("Virtual Light", "img/lightoff.png", "http://localhost:8080/data", .25)
light.add_timeseries("/lights/light0/on", "State")
light.adjust_image("/lights/light0/on", get_image)
light.add_timeseries("/lights/light0/bri", "Brightness")
light.add_table()
light.finish()

def run():
    device.main()

if __name__ == '__main__':
    device.main()
