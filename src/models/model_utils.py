import os
import sys

# Get the directory where the current script is located
current_dir = os.path.dirname(os.path.abspath(__file__)).split('\\')

# Construct the path to your target folder (e.g., 'data' inside the repo)
target_folder = "/".join(current_dir[:current_dir.index('src')+1])
sys.path.append(os.path.abspath(target_folder))

import torch
from sklearn.metrics import precision_recall_fscore_support

from models.model_definition import ViT
from models.model_config import UnswConfig, CicIdsConfig, BaseConfig
from models.dataset_definition import UnswNb15, CicIds2017


def precision_recall_f1(predictions, labels):
    y_pred = []
    y_true = []
    for x, y in zip(predictions, labels):
        y_pred.append(x)
        y_true.append(list(y).index(1.0))

    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="macro")
    return p, r, f1


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
