from sniffer.packet import PacketInfo


TIMEOUT = 60


class FlowControl:
    active: dict[frozenset:list]
    closed: dict[frozenset:list]
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
