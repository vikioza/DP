import pyshark

# local import
from config import Interfaces


def capture_packets():
    interface = Interfaces.ETHERNET
    # capture = pyshark.LiveCapture(interface=interface)
    capture = pyshark.LiveCapture(interface=interface, use_ek=True, include_raw=True)
    for packet in capture.sniff_continuously(packet_count=10):
        # replace with packet processing pipeline
        try:
            # print(dir(packet))
            print(f"layers in packet: {packet.layers}")
            if "tcp" in packet:
                print(f"ports: {packet.tcp.port.value}")
                print(f"len: {packet.tcp.len}")
                flag_fields = packet.tcp.flags.subfields
                flag_fields.remove('str')
                flag_fields.remove('raw')
                flags = {flag: packet.tcp.flags.get_field(flag).value for flag in flag_fields}
                print(flags)
                #     # print(dir(packet.tcp.flags.get_field(flag)))
                #     print(packet.tcp.flags.get_field(flag).raw)
                # if "payload" in packet.tcp:
                # if packet.tcp.get("payload") is not None:
                #     print(bytearray(packet.tcp.payload.raw))
                if packet.tcp.has_field("payload"):
                    barr = bytearray(packet.tcp.payload.value)
                    print([int(byte) for byte in barr])
                print("\n\n")
            # elif "udp" in packet:
            #     print(packet.udp)
            # if "ip" in packet:
            #     print(packet.ip.src)
            #     print(packet.ip.dst)
            #     print(packet.ip.proto)
            #     print(packet.ip.ttl)
            #     print(packet.ip.len)
            #     print(packet.ip.flags)
            # if "tcp" in packet:
            #     print(packet.tcp)
        except TypeError:
            continue


if __name__ == "__main__":
    capture_packets()
