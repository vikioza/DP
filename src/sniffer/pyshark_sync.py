import pyshark
import time
import torch

# local import
from config import Interfaces
from packet import PacketInfo
from data_processing.feature_procesing import convert_feature_to_rgb_image
from src.models.model_definition import ViT
from src.models.model_config import ModelConfig


def capture_packets():
    # load model
    # model = ViT(
    #     ModelConfig.NUM_PATCHES,
    #     ModelConfig.NUM_CLASSES,
    #     ModelConfig.PATCH_SIZE,
    #     ModelConfig.EMBED_DIM,
    #     ModelConfig.NUM_ENCODERS,
    #     ModelConfig.NUM_HEADS,
    #     ModelConfig.DROPOUT,
    #     ModelConfig.ACTIVATION,
    #     ModelConfig.IN_CHANNELS,
    # )
    # model.load_state_dict(torch.load('C:\VScode_Projects\DP\src\models\saved\model_unsw_payload'))
    # model.to(ModelConfig.DEVICE)
    # model.eval()

    # interface = Interfaces.ETHERNET
    interface = Interfaces.TOWER_ETHERNET
    start_time = time.time()
    capture = pyshark.LiveCapture(interface=interface, use_ek=True, include_raw=True)
    for packet in capture.sniff_continuously(packet_count=5):
        # replace with packet processing pipeline
        try:
            # # elif "udp" in packet:
            #     print(packet.udp)
            info = PacketInfo(packet, start_time)
            if info.has_payload:
                convert_feature_to_rgb_image(info.features)
        except TypeError:
            continue


if __name__ == "__main__":

    capture_packets()
