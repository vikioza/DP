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


def capture_packets():
    # load model
    model = ViT(
        ModelConfig.NUM_PATCHES,
        ModelConfig.NUM_CLASSES,
        ModelConfig.PATCH_SIZE,
        ModelConfig.EMBED_DIM,
        ModelConfig.NUM_ENCODERS,
        ModelConfig.NUM_HEADS,
        ModelConfig.DROPOUT,
        ModelConfig.ACTIVATION,
        ModelConfig.IN_CHANNELS,
    )
    model.load_state_dict(
        torch.load("C:\VScode_Projects\DP\src\models\saved\model_unsw_payload")
    )
    model.to(ModelConfig.DEVICE)
    model.eval()
    dataset = UNSW_NB15()

    # interface = Interfaces.ETHERNET
    interface = Interfaces.TOWER_ETHERNET
    start_time = time.time()
    capture = pyshark.LiveCapture(interface=interface, use_ek=True, include_raw=True)
    for packet in capture.sniff_continuously():
        try:
            info = PacketInfo(packet, start_time)
            if info.has_payload:
                img = convert_feature_to_rgb_image(info.features, height=32, width=64)
                img = torch.from_numpy(np.array([img])).float().to(ModelConfig.DEVICE)
                prediction = model(img)
                predicted_label_idx = int(torch.argmax(prediction).detach())
                print(
                    f"Packet {info.readable_id} - Prediction: {dataset.classes_list[predicted_label_idx]}"
                )
            else:
                print("no payload")
        except TypeError as te:
            print(te)
            continue


if __name__ == "__main__":

    capture_packets()
