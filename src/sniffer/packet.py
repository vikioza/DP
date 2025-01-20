import time
from dataclasses import dataclass

PAYLOAD_PADDING = 1500


@dataclass(init=False)
class PacketInfo:
    timestamp: float  # seconds since Epoch
    t_delta: float
    layers: list
    idset: frozenset
    internet_layer: dict = None
    transport_layer: dict = None
    payload: list = None

    def __init__(self, packet, start_time):
        self.timestamp = time.time()
        self.t_delta = self.timestamp - start_time
        self.layers = packet.layers
        if "ip" in packet:
            self._parse_ip(packet)
            if "tcp" in packet:
                self._parse_tcp(packet)
            if "udp" in packet:
                self._parse_udp(packet)

        if not self.has_payload:
            self.idset = None

    @property
    def has_payload(self):
        return True if self.payload is not None else False

    @property
    def features(self):
        header = [
            self.internet_layer.get("ttl"),
            self.internet_layer.get("len"),
            1 if self.internet_layer.get("proto") == 6 else 0,
            self.t_delta,
        ]
        payload_bytes = self.payload + [0] * (PAYLOAD_PADDING - len(self.payload))
        return header + payload_bytes

    @property
    def readable_id(self):
        return {
            "src_ip": self.internet_layer.get("src"),
            "dst_ip": self.internet_layer.get("dst"),
            "protocol": self._readable_protocol(),
            "src_p": self.transport_layer.get("ports")[0],
            "dst_p": self.transport_layer.get("ports")[1],
            "timestamp": self.timestamp,
        }

    def _parse_ip(self, packet):
        self.internet_layer = {}
        try:
            self.internet_layer["src"] = packet.ip.src.value
            self.internet_layer["dst"] = packet.ip.dst.value
            self.internet_layer["proto"] = packet.ip.proto.value
            self.internet_layer["ttl"] = packet.ip.ttl.value
            self.internet_layer["len"] = packet.ip.len.value
        except AttributeError as ae:
            print(f"Attribute error occured: {ae}")
            print(packet.ip.field_names)
            raise ae

    def _parse_tcp(self, packet):
        self.transport_layer = {}
        try:
            self.transport_layer["ports"] = packet.tcp.port.value
            self.transport_layer["len"] = packet.tcp.len

            flag_fields = packet.tcp.flags.subfields
            flag_fields.remove("str")
            flag_fields.remove("raw")
            self.transport_layer["flags"] = {
                flag: packet.tcp.flags.get_field(flag).value for flag in flag_fields
            }
        except AttributeError as ae:
            print(f"Attribute error occured: {ae}")
            print(packet.tcp.field_names)
            raise ae

        if packet.tcp.has_field("payload"):
            self.payload = [int(byte) for byte in bytearray(packet.tcp.payload.value)]
        else:
            self.payload = []

        self._freeze_id_set()

    def _parse_udp(self, packet):
        self.transport_layer = {}
        try:
            self.transport_layer["ports"] = packet.udp.port.value
            self.transport_layer["len"] = packet.udp.length
        except AttributeError as ae:
            print(f"Attribute error occured: {ae}")
            print(packet.udp.field_names)
            raise ae

        if packet.udp.has_field("payload"):
            self.payload = [int(byte) for byte in bytearray(packet.udp.payload.value)]
        else:
            self.payload = []

        self._freeze_id_set()

    def _freeze_id_set(self):
        self.idset = frozenset(
            [
                self.internet_layer.get("src"),
                self.internet_layer.get("dst"),
                self.internet_layer.get("proto"),
                self.transport_layer.get("ports")[0],
                self.transport_layer.get("ports")[1],
            ]
        )

    def _readable_protocol(self):
        if self.internet_layer.get("proto") == 1:
            return "ICMP"
        if self.internet_layer.get("proto") == 2:
            return "IGMP"
        if self.internet_layer.get("proto") == 6:
            return "TCP"
        if self.internet_layer.get("proto") == 17:
            return "UDP"
        if self.internet_layer.get("proto") == 41:
            return "IPv6"
