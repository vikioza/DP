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
from models.model_config import UnswConfig, CicIdsConfig, BaseConfig
from models.dataset_definition import UnswNb15, CicIds2017


INTERFACE = Interfaces.WIFI
# INTERFACE = Interfaces.TOWER_ETHERNET
VERBOSE = True
PAYLOAD_COMMENTS = False
DURATION = 60
BASE_MODEL = "cic"

def load_model(model_name: str, model_config: BaseConfig, classes_count: int):
    model = ViT(
        model_config.NUM_PATCHES,
        classes_count,
        model_config.PATCH_SIZE,
        model_config.EMBED_DIM,
        model_config.NUM_ENCODERS,
        model_config.NUM_HEADS,
        model_config.DROPOUT,
        model_config.ACTIVATION,
        model_config.IN_CHANNELS,
    )
    model.load_state_dict(
        torch.load(os.path.join("C:\VScode_Projects\DP\src\models\saved", model_name))
    )
    model.to(model_config.DEVICE)
    model.eval()
    return model


def load_models_unsw() -> tuple[ViT, list, ViT, list]:
    return (
        load_model("model_unsw_payload", UnswConfig, UnswConfig.NUM_CLASSES_UNSW),
        UnswNb15().classes_list,
        load_model(
            "model_unsw_payload_binary_v2", UnswConfig, UnswConfig.NUM_CLASSES_BINARY
        ),
        UnswNb15(binary=True).classes_list,
    )


def load_models_cicids() -> tuple[ViT, list, ViT, list]:
    return (
        load_model("model_cic_payload", CicIdsConfig, CicIdsConfig.NUM_CLASSES_CICIDS),
        CicIds2017().classes_list,
        load_model(
            "model_cic_payload_binary", CicIdsConfig, CicIdsConfig.NUM_CLASSES_BINARY
        ),
        CicIds2017(binary=True).classes_list,
    )


def load_models(base: str) -> tuple[ViT, list, ViT, list]:
    if base == "unsw":
        return load_models_unsw()
    return load_models_cicids()


def dump_stats(
    packet_count: int,
    normal_count: int,
    mismatch_count: int,
    unrecognized_threats: int,
    skipped_count: int,
    error_count: int,
    flows: FlowControl,
    alerts: AlertSystem,
):
    print("DUMPING STATS...")
    print(f"Total received packets: {packet_count}")
    print(f"Packets skipped: {skipped_count}")
    print(f"Errors handled during runtime: {error_count}")
    print(f"Normal packets received: {normal_count}")
    print(f"Prediction mismatches: {mismatch_count}")

    unrecognized_threats += sum([alerts.threshold for _ in alerts.threats])
    print(f"Unrecognized threats detected in {unrecognized_threats} packets!")
    flows.dump_stats()
    alerts.dump_stats()
    print("EXITING...")


def capture_packets():
    model_multi, classes_multi, model_binary, classes_binary = load_models(base=BASE_MODEL)

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

    capture_packets()
