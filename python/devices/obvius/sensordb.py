"""Database of sMAP mappings for sensors coming through the obvius
AcquiSuite tool.
"""

import SmapPoint

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
            ('I a', MAYBEFLOATPAT, 'A', 'current',
             SmapPoint.Formatting(unit='A', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('I b', MAYBEFLOATPAT, 'B', 'current',
             SmapPoint.Formatting(unit='A', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('I c', MAYBEFLOATPAT, 'C', 'current',
             SmapPoint.Formatting(unit='A', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('I demand', MAYBEFLOATPAT, 'ABC', 'current_demand',
             SmapPoint.Formatting(unit='A', multiplier=1, divisor=1, type='electric', ctype='sensor')),

            ('I a demand', MAYBEFLOATPAT, 'A', 'current_demand',
             SmapPoint.Formatting(unit='A', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('I b demand', MAYBEFLOATPAT, 'B', 'current_demand',
             SmapPoint.Formatting(unit='A', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('I c demand', MAYBEFLOATPAT, 'C', 'current_demand',
             SmapPoint.Formatting(unit='A', multiplier=1, divisor=1, type='electric', ctype='sensor')),

            ('I1 THD', MAYBEFLOATPAT, 'A', 'thd',
             SmapPoint.Formatting(unit='pct', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('I2 THD', MAYBEFLOATPAT, 'B', 'thd',
             SmapPoint.Formatting(unit='pct', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('I3 THD', MAYBEFLOATPAT, 'C', 'thd',
             SmapPoint.Formatting(unit='pct', multiplier=1, divisor=1, type='electric', ctype='sensor')),

            ('Frequency', MAYBEFLOATPAT, 'ABC', 'line_frequency',
             SmapPoint.Formatting(unit='Hz', multiplier=1, divisor=1, type='electric', ctype='sensor')),

            ('Vll AB', r'^(\d+)', 'AB', 'volts',
             SmapPoint.Formatting(unit='V', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('Vll BC', r'^(\d+)', 'BC', 'volts',
             SmapPoint.Formatting(unit='V', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('Vll CA', r'^(\d+)', 'AC', 'volts',
             SmapPoint.Formatting(unit='V', multiplier=1, divisor=1, type='electric', ctype='sensor')),

            ('kW total', r'^(\d+)', 'ABC', 'real_power',
             SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('kVA total', r'^(\d+)', 'ABC', 'apparent_power',
             SmapPoint.Formatting(unit='kVA', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('kVAR total', r'^(\d+)', 'ABC', 'reactive_power',
             SmapPoint.Formatting(unit='kVAR', multiplier=1, divisor=1, type='electric', ctype='sensor')),

            ('kW demand', r'^(\d+)', 'ABC', 'real_power_demand',
             SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('kVA demand', r'^(\d+)', 'ABC', 'apparent_power_demand',
             SmapPoint.Formatting(unit='kVA', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('kVAR demand', r'^(\d+)', 'ABC', 'reactive_power_demand',
             SmapPoint.Formatting(unit='kVAR', multiplier=1, divisor=1, type='electric', ctype='sensor')),

            ('PF sign total', r'^(-?\d+\.\d+)', 'ABC', 'pf',
             SmapPoint.Formatting(unit='PF', multiplier=1, divisor=1, type='electric', ctype='sensor'))
            ],

        "meters" : [
            ('kWh del', r'^(\d+)', 'ABC', 'true_energy',
             SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='meter')),
            ('kWh rec', r'^(\d+)', 'ABC', 'true_energy_received',
             SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='meter')),

            ('kVARh del', r'^(\d+)', 'ABC', 'reactive_energy',
             SmapPoint.Formatting(unit='kVAR', multiplier=1, divisor=1, type='electric', ctype='meter')),
            ('kVARh rec', r'^(\d+)', 'ABC', 'reactive_energy_received',
             SmapPoint.Formatting(unit='kVAR', multiplier=1, divisor=1, type='electric', ctype='meter')),

            ('kVAh del+rec', r'^(\d+)', 'ABC', 'apparent_energy_net',
             SmapPoint.Formatting(unit='kVA', multiplier=1, divisor=1, type='electric', ctype='meter')),

            ('kWh a del', r'^(\d+)', 'A', 'true_energy',
             SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='meter')),
            ('kWh a rec', r'^(\d+)', 'A', 'true_energy_received',
             SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='meter')),
            ('kWh b del', r'^(\d+)', 'B', 'true_energy',
             SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='meter')),
            ('kWh b rec', r'^(\d+)', 'B', 'true_energy_received',
             SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='meter')),
            ('kWh c del', r'^(\d+)', 'C', 'true_energy',
             SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='meter')),
            ('kWh c rec', r'^(\d+)', 'C', 'true_energy_received',
             SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='meter')),
            ]
        },
    {
        'obviusname' : 'Shark 100',
        'sensors' : [
            ('Volts A-N', MAYBEFLOATPAT, 'A', 'volts',
             SmapPoint.Formatting(unit='V', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('Volts B-N', MAYBEFLOATPAT, 'B', 'volts',
             SmapPoint.Formatting(unit='V', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('Volts C-N', MAYBEFLOATPAT, 'C', 'volts',
             SmapPoint.Formatting(unit='V', multiplier=1, divisor=1, type='electric', ctype='sensor')),

            ('Volts A-B', MAYBEFLOATPAT, 'AB', 'volts',
             SmapPoint.Formatting(unit='V', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('Volts B-C', MAYBEFLOATPAT, 'BC', 'volts',
             SmapPoint.Formatting(unit='V', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('Volts C-A', MAYBEFLOATPAT, 'AC', 'volts',
             SmapPoint.Formatting(unit='V', multiplier=1, divisor=1, type='electric', ctype='sensor')),

            ('Amps A', MAYBEFLOATPAT, 'A', 'current',
             SmapPoint.Formatting(unit='A', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('Amps B', MAYBEFLOATPAT, 'B', 'current',
             SmapPoint.Formatting(unit='A', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('Amps C', MAYBEFLOATPAT, 'C', 'current',
             SmapPoint.Formatting(unit='A', multiplier=1, divisor=1, type='electric', ctype='sensor')),

            ('Watts, 3-Ph total', r'^(\d+)', 'ABC', 'real_power',
             SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('VAs, 3-Ph total', r'^(\d+)', 'ABC', 'apparent_power',
             SmapPoint.Formatting(unit='kVA', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('VARs, 3-Ph total', r'^(\d+)', 'ABC', 'reactive_power',
             SmapPoint.Formatting(unit='kVAR', multiplier=1, divisor=1, type='electric', ctype='sensor')),

            ('Power Factor, 3-Ph total', r'^(-?\d+\.\d+)', 'ABC', 'pf',
             SmapPoint.Formatting(unit='PF', multiplier=1, divisor=1, type='electric', ctype='sensor')),

            ('Frequency', MAYBEFLOATPAT, 'ABC', 'line_frequency',
             SmapPoint.Formatting(unit='Hz', multiplier=1, divisor=1, type='electric', ctype='sensor')),

            ('Angle, Phase A Current', MAYBEFLOATPAT, 'A', 'current_phase_angle',
             SmapPoint.Formatting(unit='deg', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('Angle, Phase B Current', MAYBEFLOATPAT, 'B', 'current_phase_angle',
             SmapPoint.Formatting(unit='deg', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('Angle, Phase C Current', MAYBEFLOATPAT, 'C', 'current_phase_angle',
             SmapPoint.Formatting(unit='deg', multiplier=1, divisor=1, type='electric', ctype='sensor')),

            ('Angle, Volts A-B', MAYBEFLOATPAT, 'AB', 'volts_phase_angle',
             SmapPoint.Formatting(unit='deg', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('Angle, Volts B-C', MAYBEFLOATPAT, 'BC', 'volts_phase_angle',
             SmapPoint.Formatting(unit='deg', multiplier=1, divisor=1, type='electric', ctype='sensor')),
            ('Angle, Volts C-A', MAYBEFLOATPAT, 'AC', 'volts_phase_angle',
             SmapPoint.Formatting(unit='deg', multiplier=1, divisor=1, type='electric', ctype='sensor')),

            ],
        'meters' : [
            ('W-hours, Received', r'^(\d+)', 'ABC', 'true_energy_received',
             SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='meter')),
            ('W-hours, Delivered', r'^(\d+)', 'ABC', 'true_energy_delivered',
             SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='meter')),

            ('VAR-hours, Positive', r'^(\d+)', 'ABC', 'reactive_energy_positive',
             SmapPoint.Formatting(unit='kVAR', multiplier=1, divisor=1, type='electric', ctype='meter')),
            ('VAR-hours, Negative', r'^(\d+)', 'ABC', 'reactive_energy_negative',
             SmapPoint.Formatting(unit='kVAR', multiplier=1, divisor=1, type='electric', ctype='meter')),
            ('VAR-hours, Net', r'^(\d+)', 'ABC', 'reactive_energy_net',
             SmapPoint.Formatting(unit='kVAR', multiplier=1, divisor=1, type='electric', ctype='meter')),
            ('VAR-hours, Total', r'^(\d+)', 'ABC', 'reactive_energy_total',
             SmapPoint.Formatting(unit='kVAR', multiplier=1, divisor=1, type='electric', ctype='meter')),

            ]
        }
    ]

TYPES = [x['obviusname'] for x in DB]
