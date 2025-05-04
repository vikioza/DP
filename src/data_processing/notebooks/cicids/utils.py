import os
import h5py as h5
import numpy as np
from multiprocessing import Pool
from functools import partial


def gray_filter(img, tolerance):
    img = img / 255
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


def generate_average_image_filtered(base_path, image_folder, indices):
    with h5.File(
        os.path.join(base_path, image_folder, "binary_data.hdf5"),
        "r",
    ) as f:
        data = f["images"]
        chunks = np.array_split(indices, np.ceil(len(indices) / 10_000))
        average_per_chunk = []
        for chunk in chunks:
            images = data[chunk].astype(np.float32)
            filter_func = partial(gray_filter, tolerance=0.1)
            with Pool(16) as pool:
                filtered = pool.map(filter_func, images)
            average_per_chunk.append(np.mean(filtered, axis=0))

        summed_image = np.mean(np.array(average_per_chunk), axis=0)
        return summed_image


def generate_average_image_unfiltered(base_path, image_folder, indices):
    with h5.File(
        os.path.join(base_path, image_folder, "binary_data.hdf5"),
        "r",
    ) as f:
        data = f["images"]
        chunks = np.array_split(indices, np.ceil(len(indices) / 10_000))
        average_per_chunk = []
        for chunk in chunks:
            images = data[chunk].astype(np.float32)
            average_per_chunk.append(np.mean(images, axis=0))

        summed_image = np.mean(np.array(average_per_chunk), axis=0) / 255
        return summed_image


def generate_average_image(base_path, image_folder, indices, filter: bool = True):
    if filter:
        return generate_average_image_filtered(base_path, image_folder, indices)
    return generate_average_image_unfiltered(base_path, image_folder, indices)
