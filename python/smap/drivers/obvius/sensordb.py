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
            ('I a (Amps)', MAYBEFLOATPAT, 'A', 'current', 'A'),
            ('I b (Amps)', MAYBEFLOATPAT, 'B', 'current', 'A'),
            ('I c (Amps)', MAYBEFLOATPAT, 'C', 'current', 'A'),
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
            ('kWh del', r'^(\d+)', 'ABC', 'true_energy', 'kWh'),
            ('kWh rec', r'^(\d+)', 'ABC', 'true_energy_received', 'kWh'),

            ('kVARh del', r'^(\d+)', 'ABC', 'reactive_energy', 'kVARh'),
            ('kVARh rec', r'^(\d+)', 'ABC', 'reactive_energy_received', 'kVARh'),

            ('kVAh del+rec', r'^(\d+)', 'ABC', 'apparent_energy_net', 'kVAh'),

            ('kWh a del', r'^(\d+)', 'A', 'true_energy', 'kWh'),
            ('kWh a rec', r'^(\d+)', 'A', 'true_energy_received', 'kWh'),
            ('kWh b del', r'^(\d+)', 'B', 'true_energy', 'kWh'),
            ('kWh b rec', r'^(\d+)', 'B', 'true_energy_received', 'kWh'),
            ('kWh c del', r'^(\d+)', 'C', 'true_energy', 'kWh'),
            ('kWh c rec', r'^(\d+)', 'C', 'true_energy_received', 'kWh'),
            ]
        },
    {
        'obviusname' : 'Shark 100',
        'sensors' : [
            ('Volts A-N (Volts)', MAYBEFLOATPAT, 'A', 'volts', 'V'),
            ('Volts B-N (Volts)', MAYBEFLOATPAT, 'B', 'volts', 'V'),
            ('Volts C-N (Volts)', MAYBEFLOATPAT, 'C', 'volts', 'V'),

            ('Volts A-B (Volts)', MAYBEFLOATPAT, 'AB', 'volts', 'V'),
            ('Volts B-C (Volts)', MAYBEFLOATPAT, 'BC', 'volts', 'V'),
            ('Volts C-A (Volts)', MAYBEFLOATPAT, 'AC', 'volts', 'V'),

            ('Amps A (Amps)', MAYBEFLOATPAT, 'A', 'current', 'A'),
            ('Amps B (Amps)', MAYBEFLOATPAT, 'B', 'current', 'A'),
            ('Amps C (Amps)', MAYBEFLOATPAT, 'C', 'current', 'A'),

            ('Watts, 3-Ph total', r'^(\d+)', 'ABC', 'real_power', 'kW'),
            ('VAs, 3-Ph total', r'^(\d+)', 'ABC', 'apparent_power', 'kVA'),
            ('VARs, 3-Ph total', r'^(\d+)', 'ABC', 'reactive_power', 'kVAR'),

            ('Power Factor, 3-Ph total', r'^(-?\d+\.\d+)', 'ABC', 'pf', 'PF'),

            ('Frequency (Hz)', MAYBEFLOATPAT, 'ABC', 'line_frequency', 'Hz'),

            ('Angle, Phase A Current', MAYBEFLOATPAT, 'A', 'current_phase_angle', 'deg'),
            ('Angle, Phase B Current', MAYBEFLOATPAT, 'B', 'current_phase_angle', 'deg'),
            ('Angle, Phase C Current', MAYBEFLOATPAT, 'C', 'current_phase_angle', 'deg'),

            ('Angle, Volts A-B', MAYBEFLOATPAT, 'AB', 'volts_phase_angle', 'deg'),
            ('Angle, Volts B-C', MAYBEFLOATPAT, 'BC', 'volts_phase_angle', 'deg'),
            ('Angle, Volts C-A', MAYBEFLOATPAT, 'AC', 'volts_phase_angle', 'deg'),

            ],
        'meters' : [
            ('W-hours, Received', r'^(\d+)', 'ABC', 'true_energy_received', 'kWh'),
            ('W-hours, Delivered', r'^(\d+)', 'ABC', 'true_energy_delivered', 'kWh'),

            ('VAR-hours, Positive', r'^(\d+)', 'ABC', 'reactive_energy_positive', 'kVARh+'),
            ('VAR-hours, Negative', r'^(\d+)', 'ABC', 'reactive_energy_negative', 'kVARh-'),
            ('VAR-hours, Net', r'^(\d+)', 'ABC', 'reactive_energy_net', 'kVAR net'),
            ('VAR-hours, Total', r'^(\d+)', 'ABC', 'reactive_energy_total', 'kVARh'),

            ]
        },
    {
        'obviusname' : 'AcquiSuite 8811-1 Internal 4A4P-M2',
        'locations' : ['Soda Hall'],
        'meters' : [
            ('Steam (Lbs)', r'^(\d)+', 'steam', 'total', 'Lbs'),
            ('Steam Rate', r'^(\d)+', 'steam', 'rate', 'Lbs/hr'),
            ('Electric Main #1 (#...213) (kWh)', r'^(\d)+', 'electric_1', 'true_energy_received', 'kWh'),
            ('Electric Main #1 (#...213) Demand (kW)', r'^(\d)+', 'electric_1', 'real_power', 'kW'),
            ('Electric Main #2 (#...378) (kWh)', r'^(\d)+', 'electric_2', 'true_energy_received', 'kWh'),
            ('Electric Main #2 (#...378) Demand (kW)', r'^(\d)+', 'electric_2', 'real_power', 'kW'),
            
            ],
        'sensors' : []
        },
    {
        'obviusname' : 'Power Measurement ION 7330',
        "sensors" : [
            ('I a (Amps)', MAYBEFLOATPAT, 'A', 'current', 'A'),
            ('I b (Amps)', MAYBEFLOATPAT, 'B', 'current', 'A'),
            ('I c (Amps)', MAYBEFLOATPAT, 'C', 'current', 'A'),

            ('I1 THD', MAYBEFLOATPAT, 'A', 'thd', 'pct'),
            ('I2 THD', MAYBEFLOATPAT, 'B', 'thd', 'pct'),
            ('I3 THD', MAYBEFLOATPAT, 'C', 'thd', 'pct'),

            ('Freq (Hz)', MAYBEFLOATPAT, 'ABC', 'line_frequency', 'Hz'),

            ('Vll ab', r'^(\d+)', 'AB', 'volts', 'V'),
            ('Vll bc', r'^(\d+)', 'BC', 'volts', 'V'),
            ('Vll ca', r'^(\d+)', 'AC', 'volts', 'V'),

            ('kW tot (kW)', r'^(\d+)', 'ABC', 'real_power', 'kW'),
            ('kVA tot (kVA)', r'^(\d+)', 'ABC', 'apparent_power', 'kVA'),
            ('kVAR tot (kVAR)', r'^(\d+)', 'ABC', 'reactive_power', 'kVAR'),

            ('kW td (kW)', r'^(\d+)', 'ABC', 'real_power_demand', 'kW'),
            ('kVA td (kVA)', r'^(\d+)', 'ABC', 'apparent_power_demand', 'kVA'),
            ('kVAR td (kVAR)', r'^(\d+)', 'ABC', 'reactive_power_demand', 'kVAR'),

            ('PF sign tot', r'^(-?\d+\.\d+)', 'ABC', 'pf', 'PF')
            ],

        "meters" : [
            ('kWh del (kWh)', r'^(\d+)', 'ABC', 'true_energy', 'kWh'),
            ('kWh rec (kWh)', r'^(\d+)', 'ABC', 'true_energy_received', 'kWh'),

            ('kVARh del (kVARh)', r'^(\d+)', 'ABC', 'reactive_energy', 'kVARh'),
            ('kVARh rec (kVARh)', r'^(\d+)', 'ABC', 'reactive_energy_received', 'kVARh'),

            ('kVAh', r'^(\d+)', 'ABC', 'apparent_energy_net', 'kVAh'),
            ]
        },
    {
        'obviusname' : 'Power Measurement ION 7300',
        "sensors" : [
            ('I a (Amps)', MAYBEFLOATPAT, 'A', 'current', 'A'),
            ('I b (Amps)', MAYBEFLOATPAT, 'B', 'current', 'A'),
            ('I c (Amps)', MAYBEFLOATPAT, 'C', 'current', 'A'),

            ('I1 THD', MAYBEFLOATPAT, 'A', 'thd', 'pct'),
            ('I2 THD', MAYBEFLOATPAT, 'B', 'thd', 'pct'),
            ('I3 THD', MAYBEFLOATPAT, 'C', 'thd', 'pct'),

            ('Freq (Hz)', MAYBEFLOATPAT, 'ABC', 'line_frequency', 'Hz'),

            ('Vll ab', r'^(\d+)', 'AB', 'volts', 'V'),
            ('Vll bc', r'^(\d+)', 'BC', 'volts', 'V'),
            ('Vll ca', r'^(\d+)', 'AC', 'volts', 'V'),

            ('kW tot (kW)', r'^(\d+)', 'ABC', 'real_power', 'kW'),
            ('kVA tot (kVA)', r'^(\d+)', 'ABC', 'apparent_power', 'kVA'),
            ('kVAR tot (kVAR)', r'^(\d+)', 'ABC', 'reactive_power', 'kVAR'),

            ('kW td (kW)', r'^(\d+)', 'ABC', 'real_power_demand', 'kW'),
            ('kVA td (kVA)', r'^(\d+)', 'ABC', 'apparent_power_demand', 'kVA'),
            ('kVAR td (kVAR)', r'^(\d+)', 'ABC', 'reactive_power_demand', 'kVAR'),

            ('PF sign tot', r'^(-?\d+\.\d+)', 'ABC', 'pf', 'PF')
            ],

        "meters" : [
            ('kWh del (kWh)', r'^(\d+)', 'ABC', 'true_energy', 'kWh'),
            ('kWh rec (kWh)', r'^(\d+)', 'ABC', 'true_energy_received', 'kWh'),

            ('kVARh del (kVARh)', r'^(\d+)', 'ABC', 'reactive_energy', 'kVARh'),
            ('kVARh rec (kVARh)', r'^(\d+)', 'ABC', 'reactive_energy_received', 'kVARh'),

            ('kVAh', r'^(\d+)', 'ABC', 'apparent_energy_net', 'kVAh'),
            ]
        },
    {
        "obviusname" : "Continental Control Systems LLC, WattNode MODBUS",
        "sensors" : [
            ('Energy Sum (k)', MAYBEFLOATPAT, 'ABC', 'energy_sum', 'kWh'),
            ('Power Sum (kW)', MAYBEFLOATPAT, 'ABC', 'power_sum', 'kW'),
            ('Power A (kW)', MAYBEFLOATPAT, 'A', 'energy_sum', 'kW'),
            ('Power B (kW)', MAYBEFLOATPAT, 'B', 'energy_sum', 'kW'),
            ('Power C (kW)', MAYBEFLOATPAT, 'C', 'energy_sum', 'kW'),
            ('Voltage A (Volts)', MAYBEFLOATPAT, 'A', 'volts', 'V'),
            ('Voltage B (Volts)', MAYBEFLOATPAT, 'B', 'volts', 'V'),
            ('Voltage C (Volts)', MAYBEFLOATPAT, 'C', 'volts', 'V'),
            ('Voltage Ave LL (Volts)', MAYBEFLOATPAT, 'ABC', 'volts', 'V'),
            ('Voltage A-B (Volts)', MAYBEFLOATPAT, 'AB', 'volts', 'V'),
            ('Voltage B-C (Volts)', MAYBEFLOATPAT, 'BC', 'volts', 'V'),
            ('Voltage A-C (Volts)', MAYBEFLOATPAT, 'AC', 'volts', 'V'),
            ('Frequency (Hz)', MAYBEFLOATPAT, 'ABC', 'line_frequency', 'Hz'),
            ('Energy A Net (kWh)', MAYBEFLOATPAT, 'A', 'energy_net', 'kWh'),
            ('Energy B Net (kWh)', MAYBEFLOATPAT, 'B', 'energy_net', 'kWh'),
            ('Energy C Net (kWh)', MAYBEFLOATPAT, 'C', 'energy_net', 'kWh'),
            ('Energy Pos A (kWh)', MAYBEFLOATPAT, 'A', 'energy_pos', 'kWh'),
            ('Energy Pos B (kWh)', MAYBEFLOATPAT, 'B', 'energy_pos', 'kWh'),
            ('Energy Pos C (kWh)', MAYBEFLOATPAT, 'C', 'energy_pos', 'kWh'),
            ('Energy Neg Sum (kWh)', MAYBEFLOATPAT, 'ABC', 'energy_neg', 'kWh'),
            ('Energy Neg Sum NR (kWh)', MAYBEFLOATPAT, 'ABC', 'energy_neg_nr', 'kWh'),
            ('Energy Neg A (kWh)', MAYBEFLOATPAT, 'A', 'energy_neg', 'kWh'),
            ('Energy Neg B (kWh)', MAYBEFLOATPAT, 'B', 'energy_neg', 'kWh'),
            ('Energy Neg C (kWh)', MAYBEFLOATPAT, 'C', 'energy_neg', 'kWh'),
            ('Energy Reactive Sum (kVARh)', MAYBEFLOATPAT, 'ABC', 'reactive_energy', 'kVARh'),
            ('Energy Reactive A (kVARh)', MAYBEFLOATPAT, 'A', 'reactive_energy', 'kVARh'),
            ('Energy Reactive B (kVARh)', MAYBEFLOATPAT, 'B', 'reactive_energy', 'kVARh'),
            ('Energy Reactive C (kVARh)', MAYBEFLOATPAT, 'C', 'reactive_energy', 'kVARh'),
            ('Energy Apparent Sum (kVAh)', MAYBEFLOATPAT, 'ABC', 'apparent_energy', 'kVAh'),
            ('Energy Apparent A (kVAh)', MAYBEFLOATPAT, 'A', 'apparent_energy', 'kVAh'),
            ('Energy Apparent B (kVAh)', MAYBEFLOATPAT, 'B', 'apparent_energy', 'kVAh'),
            ('Energy Apparent C (kVAh)', MAYBEFLOATPAT, 'C', 'apparent_energy', 'kVAh'),
            ('Power Factor Ave', MAYBEFLOATPAT, 'ABC', 'pf', 'PF'),
            ('Power Factor A', MAYBEFLOATPAT, 'A', 'pf', 'PF'),
            ('Power Factor B', MAYBEFLOATPAT, 'B', 'pf', 'PF'),
            ('Power Factor C', MAYBEFLOATPAT, 'C', 'pf', 'PF'),
            ('Power Reactive Sum (kVAR)', MAYBEFLOATPAT, 'ABC', 'reactive_power', 'kVAR'),
            ('Power Reactive A (kVAR)', MAYBEFLOATPAT, 'A', 'reactive_power', 'kVAR'),
            ('Power Reactive B (kVAR)', MAYBEFLOATPAT, 'B', 'reactive_power', 'kVAR'),
            ('Power Reactive C (kVAR)', MAYBEFLOATPAT, 'C', 'reactive_power', 'kVAR'),
            ('Power Apparent Sum (kVA)', MAYBEFLOATPAT, 'ABC', 'apparent_power', 'kVA'),
            ('Power Apparent A (kVA)', MAYBEFLOATPAT, 'A', 'apparent_power', 'kVA'),
            ('Power Apparent B (kVA)', MAYBEFLOATPAT, 'B', 'apparent_power', 'kVA'),
            ('Power Apparent C (kVA)', MAYBEFLOATPAT, 'C', 'apparent_power', 'kVA'),
            ('Current A (Amps)', MAYBEFLOATPAT, 'A', 'current', 'A'),
            ('Current B (Amps)', MAYBEFLOATPAT, 'B', 'current', 'A'),
            ('Current C (Amps)', MAYBEFLOATPAT, 'C', 'current', 'A'),
#             ('Demand (kW)', MAYBEFLOATPAT, 'ABC', '', ''),
#             ('Demand Min (kW)', MAYBEFLOATPAT, 'ABC', '', ''),
#             ('Demand Max (kW)', MAYBEFLOATPAT, 'ABC', '', ''),
#             ('Demand Apparent (kVA)', MAYBEFLOATPAT, 'ABC', '', ''),
#             ('Demand A (kW)', MAYBEFLOATPAT, 'ABC', '', ''),
#             ('Demand B (kW)', MAYBEFLOATPAT, 'ABC', '', ''),
#             ('Demand C (kW)', MAYBEFLOATPAT, 'ABC', '', '') 
            ],
        "meters" : [],
        }
    ]

TYPES = [x['obviusname'] for x in DB]
def get_map(type, location=None):
    for m in DB:
        if type.startswith(m['obviusname']) and ( \
            location == None or not 'locations' in m or location in m['locations']):
            return m
    return None
