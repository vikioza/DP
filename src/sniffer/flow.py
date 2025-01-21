from dataclasses import dataclass


@dataclass
class FlowControl:
    active = {}
    closed = {}
