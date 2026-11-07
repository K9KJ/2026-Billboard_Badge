"""Repeat CQ on SAO Port 2 using hardware-timed pulses."""

from machine import Pin
from esp32 import RMT

LED_PIN = 4  # SAO Port 2 GPIO1, as mapped in lib/sao.py
ACTIVE_HIGH = True
WORDS_PER_MINUTE = 13
WORD_GAPS = 3
CLOCK_DIVIDER = 255
RMT_CHANNEL = 0
_transmitters = {}


def pulse_levels():
    """One Morse unit per element, including the gap between repetitions."""
    levels = []
    letters = ("-.-.", "--.-")
    for letter_index, symbols in enumerate(letters):
        for symbol_index, symbol in enumerate(symbols):
            levels.extend([int(ACTIVE_HIGH)] * (3 if symbol == "-" else 1))
            if symbol_index < len(symbols) - 1:
                levels.append(int(not ACTIVE_HIGH))
        gap_units = 3 if letter_index < len(letters) - 1 else 7 * WORD_GAPS
        levels.extend([int(not ACTIVE_HIGH)] * gap_units)
    return tuple(levels)


def start(pin_number=LED_PIN, channel=RMT_CHANNEL):
    """Start a repeating RMT sequence independent of the Python event loop."""
    if channel in _transmitters:
        return _transmitters[channel]
    unit_ticks = int(RMT.source_freq() * 1.2 /
                     (WORDS_PER_MINUTE * CLOCK_DIVIDER) + 0.5)
    pin = Pin(pin_number, Pin.OUT, value=int(not ACTIVE_HIGH))
    transmitter = RMT(channel, pin=pin, clock_div=CLOCK_DIVIDER,
                      idle_level=not ACTIVE_HIGH)
    try:
        transmitter.loop(True)
        transmitter.write_pulses(unit_ticks, pulse_levels())
    except Exception:
        transmitter.deinit()
        raise
    _transmitters[channel] = transmitter
    print("Morse: CQ at", WORDS_PER_MINUTE, "WPM on GPIO", pin_number)
    return transmitter
