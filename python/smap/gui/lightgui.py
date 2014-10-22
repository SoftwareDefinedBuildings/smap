import device
import requests

"""
How many rows? -- how ever many timeseries
How many columns? -- the max number of discrete points for an actuator: at least 2

"""


light = device.Device("Virtual Light", "/home/gabe/src/smapgtk/img/lighton.png", "http://localhost:8080/data", 1)
light.add_timeseries("/lights/light0/on", "State")
light.add_timeseries("/lights/light0/bri", "Brightness")
light.add_table()
light.finish()

def run():
    device.main()

if __name__ == '__main__':
    device.main()
