from typing import Tuple
import pandas as pd
import numpy as np
import cv2
from processing_config import BaseConfig


def translate_encoded_label(labels: list, encoded_label):
    return labels[list(encoded_label).index(1)]


def load_dataset(config: BaseConfig) -> Tuple[np.array, np.array]:
    df = pd.read_csv(config.INPUT_FILE_NAME)
    df = df.drop_duplicates()
    df.protocol = df.protocol.apply(lambda x: 1 if x == "tcp" else 0)

    labels = df.label.unique()

    df = pd.get_dummies(df, columns=["label"])
    df = df.to_numpy()

    # normalize payload, ttl, total_len
    for col_index in range(df.shape[1] - 17):
        column = df[:, col_index]
        column_normalized = (column - np.min(column)) / (
            np.max(column) - np.min(column)
        )
        df[:, col_index] = column_normalized

    # normalize t_delta
    column = df[:, -16]
    column_normalized = (column - np.min(column)) / (np.max(column) - np.min(column))
    df[:, -16] = column_normalized
    df = df.astype(np.float16)

    return df, labels


def save_dataset_as_images(arr: np.array, config: BaseConfig) -> None:
    with open(config.OUTPUT_CSV_FILE, "w") as f:
        np.savetxt(f, [np.array(["file_name", "label"])], delimiter=",", fmt="%s")

        for idx, row in enumerate(arr):
            data = row[:-1]
            label = row[-1]
            if idx % 10_000 == 0:
                print(idx, label)

            data = np.pad(
                data, pad_width=int((config.SIZE - len(data)) / 2), constant_values=0
            )
            data = data.reshape(config.HEIGHT, config.WIDTH)

            channel_1 = data.astype("float64")
            channel_2 = np.rot90(channel_1, k=2).reshape(config.HEIGHT, config.WIDTH)
            channel_3 = np.rot90(channel_2, k=2).reshape(config.HEIGHT, config.WIDTH)
            img = np.stack((channel_1, channel_2, channel_3)).transpose((1, 2, 0))

            file_name = config.IMG_FILE_NAME_TEMPLATE.format(idx=idx)
            cv2.imwrite(config.PATH + "\image\\" + file_name, img * 255)

            log = np.array([file_name, label])
            np.savetxt(f, [log], delimiter=",", fmt="%s")
    print("DONE")


def save_dataset_as_serialized_images(
    arr: np.array, config: BaseConfig, shuffle: bool = False
) -> None:
    if shuffle:
        np.random.shuffle(arr)

    with open(config.OUTPUT_CSV_FILE, "w") as f:
        np.savetxt(f, [np.array(["file_name", "label"])], delimiter=",", fmt="%s")

        for idx in range(len(arr) - 5):
            batch = arr[idx : idx + 5, :-15]
            label = translate_encoded_label(arr[idx + 5, -15:])
            data = np.concatenate(batch)
            if idx % 10_000 == 0:
                print(idx, label)

            data = np.pad(
                data, pad_width=int((config.SIZE - len(data)) / 2), constant_values=0
            )
            data = data.reshape(config.HEIGHT, config.WIDTH)

            channel_1 = data.astype("float64")
            channel_2 = np.rot90(channel_1, k=2).reshape(config.HEIGHT, config.WIDTH)
            channel_3 = np.rot90(channel_2, k=2).reshape(config.HEIGHT, config.WIDTH)
            img = np.stack((channel_1, channel_2, channel_3)).transpose((1, 2, 0))

            file_name = config.IMG_FILE_NAME_TEMPLATE.format(idx=idx)
            cv2.imwrite(config.PATH + "\image_serialized_5\\" + file_name, img * 255)

            log = np.array([file_name, label])
            np.savetxt(f, [log], delimiter=",", fmt="%s")
    print("DONE")
