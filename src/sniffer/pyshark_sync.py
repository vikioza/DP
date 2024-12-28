import pyshark

# local import
from config import Interfaces


def capture_packets():
    interface = Interfaces.ETHERNET
    capture = pyshark.LiveCapture(interface=interface, use_ek=True, include_raw=True)

    for packet in capture.sniff_continuously():
        # replace with packet processing pipeline
        try:
            print(packet)
        except TypeError:
            continue


if __name__ == "__main__":
    capture_packets()
