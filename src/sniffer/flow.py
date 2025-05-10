import os
import sys

# Get the directory where the current script is located
current_dir = os.path.dirname(os.path.abspath(__file__)).split('\\')

# Construct the path to your target folder (e.g., 'data' inside the repo)
target_folder = "/".join(current_dir[:current_dir.index('src')+1])
sys.path.append(os.path.abspath(target_folder))

from sniffer.packet import PacketInfo


TIMEOUT = 60


class FlowControl:
    active: dict[frozenset : list | dict]
    closed: dict[frozenset : list | dict]
    verbose: bool

    def __init__(self, verbose: bool = False):
        self.active = {}
        self.closed = {}
        self.verbose = verbose

    def dump_stats(self):
        print("FLOW STATS WIP...")
        print(f"Closed flows: {len(self.closed)}")
        print(f"Flows remaining active on exit: {len(self.active)}")
        print("Closing active flows...")
        self._cleanup_on_exit()
        print(f"Total flows: {len(self.closed)}")

    def attach(self, info: PacketInfo):
        if info.idset not in self.active:
            self.active[info.idset] = []

        self.active.get(info.idset).append(info)

        flags = info.transport_layer.get("flags")
        if flags is not None:
            fin = flags.get("fin")
            rst = flags.get("reset")
            if fin is not None or rst is not None:
                self.closed[info.idset] = self.active.pop(info.idset)

    @property
    def timeout_window(self):
        return TIMEOUT * 2

    def timeout_eligible_flows(self, current_time):
        if self.verbose:
            print("CLOSING TIMED OUT FLOWS")
        temp = {}
        for idset, flow in self.active.items():
            if current_time - flow[-1].timestamp > TIMEOUT:
                temp[idset] = self.active.get(idset)
        for idset, flow in temp.items():
            self.active.pop(idset)
            self.closed[idset] = flow

    def _cleanup_on_exit(self):
        temp = {}
        for idset, packet in self.active.items():
            temp[idset] = self.active.get(idset)
        for idset, packet in temp.items():
            self.active.pop(idset)
            self.closed[idset] = packet

    def _calculate_flow_metadata(self, flow: list[PacketInfo]):
        return None  # TODO

    def attach_dict(
        self, idset, data, srcip, window_size: int = 5, uni_dir: bool = False
    ):
        if idset not in self.active:
            if idset in self.closed:
                self.active[idset] = self.closed[idset]
                self.closed.pop(idset, None)
            else:
                self.active[idset] = {"inc": [], "out": [], "srcip": srcip}

        if self.active[idset]["srcip"] == srcip:
            self.active[idset]["inc"].append(data)
        elif uni_dir:
            self.active[idset]["inc"].append(data)
        else:
            self.active[idset]["out"].append(data)

        if len(self.active[idset]["inc"]) >= window_size:
            output_inc = self.active[idset]["inc"][-window_size:]
        else:
            output_inc = self.active[idset]["inc"]

        if len(self.active[idset]["out"]) >= window_size:
            output_out = self.active[idset]["out"][-window_size:]
        else:
            output_out = self.active[idset]["out"]

        return output_inc, output_out
    
    def cleanup(self):
        self.closed = self.active
        self.active = {}


if __name__ == "__main__":
    sample_data = [
        "bla",
        "bleh",
        "bla",
        "bleh",
        "bla",
        "bla",
        "bla",
        "bla",
        "gu",
        "bla",
    ]
    sample_ip = ["1", "2", "1", "2", "1", "1", "1", "1", "3", "1"]
    idset = [
        frozenset({"1"}),
        frozenset({"1"}),
        frozenset({"1"}),
        frozenset({"1"}),
        frozenset({"1"}),
        frozenset({"1"}),
        frozenset({"1"}),
        frozenset({"1"}),
        frozenset({"3"}),
        frozenset({"1"}),
    ]

    flows = FlowControl()
    for idx, _ in enumerate(sample_data):
        print(flows.attach_dict(idset[idx], sample_data[idx], sample_ip[idx]))

    print(flows.active)

    flows.active = {}
    for idx, _ in enumerate(sample_data):
        print(
            flows.attach_dict(
                idset[idx], sample_data[idx], sample_ip[idx], uni_dir=True
            )
        )
    print(flows.active)
