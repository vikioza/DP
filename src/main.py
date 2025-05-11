import sys
import pyshark
import time
import torch
import numpy as np

# local import
from utils import dump_stats
from sniffer.alert import AlertSystem
from sniffer.config import Interfaces
from sniffer.flow import FlowControl
from sniffer.packet import PacketInfo
from data_processing.feature_procesing import convert_feature_to_rgb_image
from models.model_config import BaseConfig
from models.model_utils import load_models


# INTERFACE = Interfaces.WIFI
INTERFACE = Interfaces.TOWER_ETHERNET
VERBOSE = True
PAYLOAD_COMMENTS = False
DURATION = 1200
BASE_MODEL = "unsw"


def capture_packets():
    model_multi, classes_multi, model_binary, classes_binary = load_models(
        base=BASE_MODEL
    )

    alerts = AlertSystem(verbose=VERBOSE)
    flows = FlowControl(verbose=VERBOSE)

    packet_count = 0
    error_count = 0
    normal_count = 0
    mismatch_count = 0
    unrecognized_threats = 0
    skipped_count = 0

    start_time = time.time()
    last_timeout_window_time = start_time
    capture = pyshark.LiveCapture(interface=INTERFACE, use_ek=True, include_raw=True)
    for packet in capture.sniff_continuously():
        packet_count += 1
        try:
            info = PacketInfo(packet=packet, start_time=start_time)
            flows.attach(info=info)
            if info.has_payload:
                img = convert_feature_to_rgb_image(
                    features=info.features, height=32, width=64
                )
                img = torch.from_numpy(np.array([img])).float().to(BaseConfig.DEVICE)
                prediction_multi = model_multi(img)
                predicted_label_multi_idx = int(torch.argmax(prediction_multi).detach())
                prediction_binary = model_binary(img)
                predicted_label_binary_idx = int(
                    torch.argmax(prediction_binary).detach()
                )

                label_multi = classes_multi[predicted_label_multi_idx]
                label_binary = classes_binary[predicted_label_binary_idx]

                if label_binary == "normal":
                    normal_count += (
                        1 if (label_multi == "normal" or label_multi == "BENIGN") else 0
                    )
                    mismatch_count += (
                        1
                        if (label_multi != "normal" and label_multi != "BENIGN")
                        else 0
                    )

                if label_binary == "anomaly":
                    alerts.alert_for(info=info)
                    if label_multi == "normal" or label_multi == "BENIGN":
                        unrecognized_threats += 1 if alerts.is_threat(info=info) else 0

                if PAYLOAD_COMMENTS:
                    print(
                        f"Packet {info.readable_id} - Predictions: {label_binary} : {label_multi}"
                    )
            else:
                skipped_count += 1

            current_time = time.time()
            if current_time - start_time > DURATION:
                print("TIMER RAN OUT, STOPPING CAPTURE...")
                break

            if current_time - last_timeout_window_time > flows.timeout_window:
                last_timeout_window_time = current_time
                flows.timeout_eligible_flows(current_time)

        except TypeError as te:
            print(te)
            error_count += 1
            continue

    dump_stats(
        packet_count,
        normal_count,
        mismatch_count,
        unrecognized_threats,
        skipped_count,
        error_count,
        flows,
        alerts,
    )


if __name__ == "__main__":
    original_stdout = sys.stdout
    with open("output-log.txt", "w") as f:
        sys.stdout = f
        capture_packets()
    sys.stdout = original_stdout
    
    # capture_packets()
