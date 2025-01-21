import numpy as np


def convert_feature_to_rgb_image(features: list, height: int, width: int):
    size = height * width
    data = np.array(features)
    data = np.pad(data, pad_width=int((size - len(data)) / 2), constant_values=0)
    data = data.reshape(height, width)

    channel_1 = data.astype("float64")
    channel_2 = np.rot90(channel_1, k=2).reshape(height, width)
    channel_3 = np.rot90(channel_2, k=2).reshape(height, width)
    img = np.stack((channel_1, channel_2, channel_3))

    return img
