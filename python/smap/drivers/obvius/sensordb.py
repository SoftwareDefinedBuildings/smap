"""Database of sMAP mappings for sensors coming through the obvius
AcquiSuite tool.
"""

MAYBEFLOATPAT = r'^(-?\d+(\.\d+)?)'

"""Format for the entries under 'sensors' and 'meters' is a 5-tuple consisting of:
  (obvius name,
   regular expression to parse the reading value with,
   sMAP sense point name
   sMAP channel name
   sMAP formatting object)

MAYBEFLOATPAT is a regular expression which will match either an
integer or a floating point number; a lot of things seemed to be
printed this way.
"""
DB = [
    {
        "obviusname" : "Power Measurement ION 6200",
        "sensors" : [
            ('I a', MAYBEFLOATPAT, 'A', 'current', 'A'),
            ('I b', MAYBEFLOATPAT, 'B', 'current', 'A'),
            ('I c', MAYBEFLOATPAT, 'C', 'current', 'A'),
            ('I demand', MAYBEFLOATPAT, 'ABC', 'current_demand', 'A'),

            ('I a demand', MAYBEFLOATPAT, 'A', 'current_demand', 'A'),
            ('I b demand', MAYBEFLOATPAT, 'B', 'current_demand', 'A'),
            ('I c demand', MAYBEFLOATPAT, 'C', 'current_demand', 'A'),

            ('I1 THD', MAYBEFLOATPAT, 'A', 'thd', 'pct'),
            ('I2 THD', MAYBEFLOATPAT, 'B', 'thd', 'pct'),
            ('I3 THD', MAYBEFLOATPAT, 'C', 'thd', 'pct'),

            ('Frequency', MAYBEFLOATPAT, 'ABC', 'line_frequency', 'Hz'),

            ('Vll AB', r'^(\d+)', 'AB', 'volts', 'V'),
            ('Vll BC', r'^(\d+)', 'BC', 'volts', 'V'),
            ('Vll CA', r'^(\d+)', 'AC', 'volts', 'V'),

            ('kW total', r'^(\d+)', 'ABC', 'real_power', 'kW'),
            ('kVA total', r'^(\d+)', 'ABC', 'apparent_power', 'kVA'),
            ('kVAR total', r'^(\d+)', 'ABC', 'reactive_power', 'kVAR'),

            ('kW demand', r'^(\d+)', 'ABC', 'real_power_demand', 'kW'),
            ('kVA demand', r'^(\d+)', 'ABC', 'apparent_power_demand', 'kVA'),
            ('kVAR demand', r'^(\d+)', 'ABC', 'reactive_power_demand', 'kVAR'),

            ('PF sign total', r'^(-?\d+\.\d+)', 'ABC', 'pf', 'PF')
            ],

        "meters" : [
            ('kWh del', r'^(\d+)', 'ABC', 'true_energy', 'kW'),
            ('kWh rec', r'^(\d+)', 'ABC', 'true_energy_received', 'kW'),

            ('kVARh del', r'^(\d+)', 'ABC', 'reactive_energy', 'kVAR'),
            ('kVARh rec', r'^(\d+)', 'ABC', 'reactive_energy_received', 'kVAR'),

            ('kVAh del+rec', r'^(\d+)', 'ABC', 'apparent_energy_net', 'kVA'),

            ('kWh a del', r'^(\d+)', 'A', 'true_energy', 'kW'),
            ('kWh a rec', r'^(\d+)', 'A', 'true_energy_received', 'kW'),
            ('kWh b del', r'^(\d+)', 'B', 'true_energy', 'kW'),
            ('kWh b rec', r'^(\d+)', 'B', 'true_energy_received', 'kW'),
            ('kWh c del', r'^(\d+)', 'C', 'true_energy', 'kW'),
            ('kWh c rec', r'^(\d+)', 'C', 'true_energy_received', 'kW'),
            ]
        },
    {
        'obviusname' : 'Shark 100',
        'sensors' : [
            ('Volts A-N', MAYBEFLOATPAT, 'A', 'volts', 'V'),
            ('Volts B-N', MAYBEFLOATPAT, 'B', 'volts', 'V'),
            ('Volts C-N', MAYBEFLOATPAT, 'C', 'volts', 'V'),

            ('Volts A-B', MAYBEFLOATPAT, 'AB', 'volts', 'V'),
            ('Volts B-C', MAYBEFLOATPAT, 'BC', 'volts', 'V'),
            ('Volts C-A', MAYBEFLOATPAT, 'AC', 'volts', 'V'),

            ('Amps A', MAYBEFLOATPAT, 'A', 'current', 'A'),
            ('Amps B', MAYBEFLOATPAT, 'B', 'current', 'A'),
            ('Amps C', MAYBEFLOATPAT, 'C', 'current', 'A'),

            ('Watts, 3-Ph total', r'^(\d+)', 'ABC', 'real_power', 'kW'),
            ('VAs, 3-Ph total', r'^(\d+)', 'ABC', 'apparent_power', 'kVA'),
            ('VARs, 3-Ph total', r'^(\d+)', 'ABC', 'reactive_power', 'kVAR'),

            ('Power Factor, 3-Ph total', r'^(-?\d+\.\d+)', 'ABC', 'pf', 'PF'),

            ('Frequency', MAYBEFLOATPAT, 'ABC', 'line_frequency', 'Hz'),

            ('Angle, Phase A Current', MAYBEFLOATPAT, 'A', 'current_phase_angle', 'deg'),
            ('Angle, Phase B Current', MAYBEFLOATPAT, 'B', 'current_phase_angle', 'deg'),
            ('Angle, Phase C Current', MAYBEFLOATPAT, 'C', 'current_phase_angle', 'deg'),

            ('Angle, Volts A-B', MAYBEFLOATPAT, 'AB', 'volts_phase_angle', 'deg'),
            ('Angle, Volts B-C', MAYBEFLOATPAT, 'BC', 'volts_phase_angle', 'deg'),
            ('Angle, Volts C-A', MAYBEFLOATPAT, 'AC', 'volts_phase_angle', 'deg'),

            ],
        'meters' : [
            ('W-hours, Received', r'^(\d+)', 'ABC', 'true_energy_received', 'kW'),
            ('W-hours, Delivered', r'^(\d+)', 'ABC', 'true_energy_delivered', 'kW'),

            ('VAR-hours, Positive', r'^(\d+)', 'ABC', 'reactive_energy_positive', 'kVAR'),
            ('VAR-hours, Negative', r'^(\d+)', 'ABC', 'reactive_energy_negative', 'kVAR'),
            ('VAR-hours, Net', r'^(\d+)', 'ABC', 'reactive_energy_net', 'kVAR'),
            ('VAR-hours, Total', r'^(\d+)', 'ABC', 'reactive_energy_total', 'kVAR'),

            ]
        }
    ]

TYPES = [x['obviusname'] for x in DB]
