import device
import requests

tstat = device.Device("Virtual Thermostat", "img/thermostat.png", "http://localhost:8080/data", 1)
tstat.add_timeseries("/thermostats/thermostat0/temp", "Temperature")
tstat.overlay_text("/thermostats/thermostat0/temp", 160, 135, "T", "Times New Roman 20")
tstat.add_timeseries("/thermostats/thermostat0/humidity", "Humidity")
tstat.overlay_text("/thermostats/thermostat0/humidity", 160, 175, "RH", "Times New Roman 20")
tstat.add_timeseries("/thermostats/thermostat0/temp_heat", "Heating Setpoint")
tstat.overlay_text("/thermostats/thermostat0/temp_heat", 300, 150, "Heat", "Times New Roman 10")
tstat.add_timeseries("/thermostats/thermostat0/temp_cool", "Cooling Setpoint")
tstat.overlay_text("/thermostats/thermostat0/temp_cool", 300, 180, "Cool", "Times New Roman 10")
tstat.add_timeseries("/thermostats/thermostat0/hvac_state", "HVAC State")
tstat.finish()

def run():
    device.main()

if __name__ == '__main__':
    device.main()
