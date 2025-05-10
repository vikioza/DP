import os
import sys

# Get the directory where the current script is located
current_dir = os.path.dirname(os.path.abspath(__file__)).split('\\')

# Construct the path to your target folder (e.g., 'data' inside the repo)
target_folder = "/".join(current_dir[:current_dir.index('src')+1])
sys.path.append(os.path.abspath(target_folder))


from dataclasses import dataclass


@dataclass()
class Interfaces:
    WIFI = "\\Device\\NPF_{C3B36434-49E1-4D30-B5A4-AEDFD3C335A8}"
    ETHERNET = "\\Device\\NPF_{1C34172C-36A2-45AF-80EA-9B08F027BBC8}"
    TOWER_ETHERNET = "\\Device\\NPF_{9F9F940B-FD75-4EB7-9B9F-BEEFF700DF9E}"
