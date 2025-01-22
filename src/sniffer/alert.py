from dataclasses import dataclass, field

from sniffer.packet import PacketInfo


@dataclass
class AlertSystem:
    warnings: dict[frozenset:list] = field(default_factory=dict)
    threats: dict[frozenset:list] = field(default_factory=dict)
    closed: dict[frozenset:list] = field(default_factory=dict)

    def alert_for(self, info: PacketInfo):
        warnings = self.warnings.get(info.idset)
        if warnings is not None:
            warnings.append(info.timestamp)
            warnings_count = len(warnings)
            if warnings_count > self._calculate_threshold():
                self._alert_threat(info)
                return
            else:
                print(f"ANOMALY DETECTED: {info.readable_id}")
                return

        threats = self.threats.get(info.idset)
        if threats is not None:
            self.threats[info.idset].append(info.timestamp)
            return

        self.warnings[info.idset] = [info.timestamp]

    def is_threat(self, info: PacketInfo):
        if self.threats.get(info.idset) is not None:
            return True
        return False

    def dump_stats(self):
        print("ALERT STATS:")
        print(f"Threats detected: {len(self.threats.keys())}")
        print(
            f"Total threatening packets detected: {sum([len(x) for x in self.threats.values()])}"
        )

        print(
            f"Flows that did not reach the threat threshold: {len(self.warnings.keys())}"
        )
        anomalies_count = sum(
            [len(x) for x in self.warnings.values()]
            + [len(x) for x in self.closed.values()]
        )
        print(f"Anomalous packets detected: {anomalies_count}")

    def close_tracked_warning(self, info: PacketInfo):
        if self.warnings.get(info.idset):
            self.closed[info.idset] += self.warnings.pop(info.idset)

    def _calculate_threshold(self):
        return 5  # TODO come up with a reasonable calculation

    def _alert_threat(self, info: PacketInfo):
        self.threats[info.idset] = self.warnings.pop(info.idset)
        print(f"THREAT DETECTED: {info.readable_id}")
        # TODO do something to handle threat
