import os
import pyshark
import time
import torch
import numpy as np

# local import
from sniffer.config import Interfaces
from sniffer.packet import PacketInfo
from data_processing.feature_procesing import convert_feature_to_rgb_image
from models.model_definition import ViT
from models.model_config import ModelConfig
from models.dataset_definition import UNSW_NB15


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


def capture_packets():
    model_payload_multi = load_model(ModelConfig.NUM_CLASSES, "model_unsw_payload")
    dataset_multi = UNSW_NB15()  # needed to explain classes # refactor!!!

    model_payload_binary = load_model(2, "model_unsw_payload_binary_v2")
    dataset_binary = UNSW_NB15(binary=True)  # needed to explain classes # refactor!!!

    # interface = Interfaces.ETHERNET
    interface = Interfaces.WIFI
    start_time = time.time()
    capture = pyshark.LiveCapture(interface=interface, use_ek=True, include_raw=True)
    for packet in capture.sniff_continuously():
        try:
            info = PacketInfo(packet, start_time)
            if info.has_payload:
                img = convert_feature_to_rgb_image(info.features, height=32, width=64)
                img = torch.from_numpy(np.array([img])).float().to(ModelConfig.DEVICE)
                prediction_multi = model_payload_multi(img)
                predicted_label_multi_idx = int(torch.argmax(prediction_multi).detach())
                prediction_binary = model_payload_binary(img)
                predicted_label_binary_idx = int(
                    torch.argmax(prediction_binary).detach()
                )

                print(
                    f"Packet {info.readable_id} - Predictions: {dataset_multi.classes_list[predicted_label_multi_idx]} : {dataset_binary.classes_list[predicted_label_binary_idx]}"
                )
            else:
                print("no payload")
        except TypeError as te:
            print(te)
            continue


if __name__ == "__main__":

    capture_packets()
