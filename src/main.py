import os
import pyshark
import sys
import time
import torch
import numpy as np

# local import
from sniffer.alert import AlertSystem
from sniffer.config import Interfaces
from sniffer.flow import FlowControl
from sniffer.packet import PacketInfo
from data_processing.feature_procesing import convert_feature_to_rgb_image
from models.model_definition import ViT
from models.model_config import ModelConfig
from models.dataset_definition import UNSW_NB15


DURATION = 300
PAYLOAD_COMMENTS = False


def load_model(classes_count, model_name):
    model = ViT(
        ModelConfig.NUM_PATCHES,
        classes_count,
        ModelConfig.PATCH_SIZE,
        ModelConfig.EMBED_DIM,
        ModelConfig.NUM_ENCODERS,
        ModelConfig.NUM_HEADS,
        ModelConfig.DROPOUT,
        ModelConfig.ACTIVATION,
        ModelConfig.IN_CHANNELS,
    )
    model.load_state_dict(
        torch.load(os.path.join("C:\VScode_Projects\DP\src\models\saved", model_name))
    )
    model.to(ModelConfig.DEVICE)
    model.eval()
    return model


def capture_packets():
    model_payload_multi = load_model(ModelConfig.NUM_CLASSES, "model_unsw_payload")
    dataset_multi = UNSW_NB15()  # needed to explain classes # refactor!!!

    model_payload_binary = load_model(2, "model_unsw_payload_binary_v2")
    dataset_binary = UNSW_NB15(binary=True)  # needed to explain classes # refactor!!!

    alerts = AlertSystem()
    flows = FlowControl()

    packet_count = 0
    error_count = 0
    normal_count = 0
    mismatch_count = 0
    unrecognized_threats = 0
    skipped_count = 0

    interface = Interfaces.WIFI
    # interface = Interfaces.TOWER_ETHERNET
    start_time = time.time()
    capture = pyshark.LiveCapture(interface=interface, use_ek=True, include_raw=True)
    for packet in capture.sniff_continuously():
        packet_count += 1
        try:
            info = PacketInfo(packet=packet, start_time=start_time)
            if info.has_payload:
                img = convert_feature_to_rgb_image(
                    features=info.features, height=32, width=64
                )
                img = torch.from_numpy(np.array([img])).float().to(ModelConfig.DEVICE)
                prediction_multi = model_payload_multi(img)
                predicted_label_multi_idx = int(torch.argmax(prediction_multi).detach())
                prediction_binary = model_payload_binary(img)
                predicted_label_binary_idx = int(
                    torch.argmax(prediction_binary).detach()
                )

                label_multi = dataset_multi.classes_list[predicted_label_multi_idx]
                label_binary = dataset_binary.classes_list[predicted_label_binary_idx]

                if label_binary == "normal" and label_multi == "normal":
                    normal_count += 1

                if label_binary == "normal" and label_multi != "normal":
                    mismatch_count += 1

                if label_binary == "anomaly":
                    alerts.alert_for(info=info)
                    if label_multi == "normal" and alerts.is_threat(info=info):
                        unrecognized_threats += 1

                if PAYLOAD_COMMENTS:
                    print(
                        f"Packet {info.readable_id} - Predictions: {label_multi} : {label_binary}"
                    )

                if time.time() - start_time > DURATION:
                    print("TIMER RAN OUT, STOPPING CAPTURE...")
                    print("DUMPING STATS...")
                    print(f"Total received packets: {packet_count}")
                    print(f"Normal packets received: {normal_count}")
                    print(f"Prediction mismatches: {mismatch_count}")
                    print(f"Unrecognized threats detected: {unrecognized_threats}")
                    print(f"Packets skipped: {skipped_count}")
                    print(f"Errors handled during runtime: {error_count}")
                    flows.dump_stats()
                    alerts.dump_stats()
                    print("EXITING...")
                    break
            else:
                skipped_count += 1
        except TypeError as te:
            print(te)
            error_count += 1
            continue


if __name__ == "__main__":

    capture_packets()
