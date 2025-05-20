import os
import sys

# Get the directory where the current script is located
current_dir = os.path.dirname(os.path.abspath(__file__)).split("\\")

# Construct the path to your target folder (e.g., 'data' inside the repo)
target_folder = "/".join(current_dir[: current_dir.index("src") + 1])
sys.path.append(os.path.abspath(target_folder))

import pandas as pd
import numpy as np
import h5py as h5
import threading
import queue

from sniffer.flow import FlowControl


HEIGHT = 128
WIDTH = 128
SIZE = HEIGHT * WIDTH
WINDOW_SIZE = 5
TOLERANCE = 0.1
PATH = "C:\VScode_Projects\DP\datasets\CIC-IDS-2017"
IMAGE_DIR_NAME = "\clean\image_uni_dir\\"
CSV_FILE = PATH + "\clean\cicids2017_img_uni_dir.csv"
IMAGE_QUEUE = queue.Queue(10_000)
LOG_QUEUE = queue.Queue()


def gray_filter(img, tolerance):
    img = img
    R, G, B = img[:, :, 0], img[:, :, 1], img[:, :, 2]
    gray_mask = np.abs(R - G) < tolerance
    img_no_gray = img.copy()
    img_no_gray[gray_mask] = [0, 0, 0]
    for c in range(3):
        channel = img_no_gray[:, :, c]
        mean = channel.mean()
        std = channel.std()
        if mean == 0 or std == 0:
            continue
        img_no_gray[:, :, c] = (channel - mean) / std
    return img_no_gray


def save_image(count: int):
    with h5.File(PATH + IMAGE_DIR_NAME + "binary_data.hdf5", "w") as f:
        dataset = f.require_dataset(
            "images", shape=(count, HEIGHT, WIDTH, 3), dtype=np.uint8
        )
        idx = 0
        while True:
            data = IMAGE_QUEUE.get()
            if data is None:
                print("THREAD DEATH")
                break

            data = data.reshape(HEIGHT, WIDTH)
            channel_1 = data.astype("float64")
            channel_2 = np.rot90(channel_1, k=2).reshape(HEIGHT, WIDTH)
            channel_3 = np.rot90(channel_2, k=2).reshape(HEIGHT, WIDTH)

            img = np.stack((channel_1, channel_2, channel_3)).transpose((1, 2, 0))
            image = gray_filter(img, TOLERANCE)

            dataset[idx] = image
            idx += 1
            IMAGE_QUEUE.task_done()


def write_to_log():
    with open(CSV_FILE, "w") as f:
        np.savetxt(
            f, [np.array(["idx", "label"])], delimiter=",", fmt="%s", encoding="utf-8"
        )
        while True:
            filename, label = LOG_QUEUE.get()
            if label is None:
                print("LOG THREAD DEATH")
                break
            log = np.array([filename, label])
            np.savetxt(f, [log], delimiter=",", fmt="%s", encoding="utf-8")


def convert_dataset_to_image(arr):
    flows = FlowControl()

    print("THREADS START")
    log_thread = threading.Thread(target=write_to_log)
    log_thread.start()
    img_thread = threading.Thread(target=save_image, args=(len(arr),))
    img_thread.start()

    for idx, row in enumerate(arr):
        idset = list(row[-4:]) + [row[-7]]
        srcip = idset[0]
        idset = frozenset(idset)
        data = row[:-5]
        label = row[-5]

        LOG_QUEUE.put((idx, label))

        data, _ = flows.attach_dict(
            idset=idset, data=data, srcip=srcip, window_size=WINDOW_SIZE, uni_dir=True
        )
        data = np.array(data).flatten()
        data = np.pad(
            data, pad_width=int((SIZE - len(data)) / 2), constant_values=0
        )

        IMAGE_QUEUE.put(data)

        if idx % 10_000 == 0:
            print(idx, label)
            flows.cleanup()

    IMAGE_QUEUE.put(None)
    img_thread.join()
    LOG_QUEUE.put((None, None))
    log_thread.join()

    print("DONE")


if __name__ == "__main__":
    print("READING CSV")
    df = pd.read_csv(PATH + "\clean\CICIDS_converted_data_final_2.csv")
    df = df.drop_duplicates()
    df.protocol = df.protocol.apply(lambda x: 1 if x == "tcp" else 0)
    print("CONVERT TO NUMPY")
    df = df.to_numpy()
    print("NORMALIZE FEATURES")
    for col_index in range(df.shape[1] - 7):
        # for col_index in range(df.shape[1] - 3):
        column = df[:, col_index]
        column_normalized = (column - np.min(column)) / (
            np.max(column) - np.min(column)
        )
        df[:, col_index] = column_normalized
    # normalize t_delta
    column = df[:, -6]
    # column = df[:, -2]
    column_normalized = (column - np.min(column)) / (np.max(column) - np.min(column))
    df[:, -6] = column_normalized
    # df[:, -2] = column_normalized

    print("PROCESS AND SAVE DATA")
    convert_dataset_to_image(df)
