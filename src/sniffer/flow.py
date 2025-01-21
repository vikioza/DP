from dataclasses import dataclass, field


@dataclass
class FlowControl:
    active: dict[frozenset:list] = field(default_factory=dict)
    closed: dict[frozenset:list] = field(default_factory=dict)

    def dump_stats(self):
        print("FLOW STATS TBD...")
