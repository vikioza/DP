from dataclasses import dataclass


@dataclass()
class Interfaces:
    WIFI = "\\Device\\NPF_{C3B36434-49E1-4D30-B5A4-AEDFD3C335A8}"
    ETHERNET = "\\Device\\NPF_{1C34172C-36A2-45AF-80EA-9B08F027BBC8}"
    TOWER_ETHERNET = "\\Device\\NPF_{9F9F940B-FD75-4EB7-9B9F-BEEFF700DF9E}"
