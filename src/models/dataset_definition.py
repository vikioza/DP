import os
import numpy as np
import pandas as pd


from torchvision import transforms
from torch.utils.data import Dataset
from torchvision.io import read_image


class UnswNb15(Dataset):
    BASE_PATH = "C:\VScode_Projects\DP\datasets\\UNSW_NB15"
    index: int
    batch_size: int
    classes_count: int
    classes_list: list

    def __init__(
        self,
        shuffle: bool = False,
        mapping_file_name: str = None,
        image_folder_name: str = None,
        binary: bool = False,
    ):
        self.mapping_file = (
            mapping_file_name if mapping_file_name is not None else "unswnb15_img.csv"
        )
        self.image_folder = (
            image_folder_name if image_folder_name is not None else "image"
        )
        self.mapping = pd.read_csv(os.path.join(self.BASE_PATH, self.mapping_file))
        if binary:
            self.mapping["label"] = self.mapping["label"].apply(
                lambda x: "normal" if x.lower() == "normal" else "anomaly"
            )
        self.mapping = pd.get_dummies(self.mapping, columns=["label"])

        if shuffle:
            self.mapping = self.mapping.sample(frac=1)  # shuffle

        self.classes_list = [label.split("_")[1] for label in self.mapping.columns[1:]]

        self.mapping = self.mapping.to_numpy()

        self.classes_count = len(self.mapping[0]) - 1

        self.transform = transforms.Compose([transforms.ToTensor()])

    def __len__(self):
        return len(self.mapping)

    def __getitem__(self, idx):
        img_name = self.mapping[idx, 0]
        img = read_image(os.path.join(self.BASE_PATH, self.image_folder, img_name))

        label = [
            1 if label_class is True else 0 for label_class in self.mapping[idx, 1:]
        ]
        label = np.array(label)

        return img, label

    def translate_encoded_label(self, encoded_label):
        return self.classes_list[list(encoded_label).index(1)]


class CicIds2017(Dataset):
    BASE_PATH = "C:\VScode_Projects\DP\datasets\CIC-IDS-2017"
    index: int
    batch_size: int
    classes_count: int
    classes_list: list

    def __init__(
        self,
        shuffle: bool = False,
        mapping_file_name: str = None,
        image_folder_name: str = None,
        binary: bool = False,
    ):
        self.mapping_file = (
            mapping_file_name if mapping_file_name is not None else "cicids2017_img.csv"
        )
        self.image_folder = (
            image_folder_name if image_folder_name is not None else "image"
        )
        self.mapping = pd.read_csv(os.path.join(self.BASE_PATH, self.mapping_file))

        if binary:
            self.mapping["label"] = self.mapping["label"].apply(
                lambda x: "normal" if x.lower() == "benign" else "anomaly"
            )
        # else:
        #     self.mapping["label"] = self.mapping["label"].apply(
        #         lambda x: "normal" if x.lower() == "benign" else x.lower()
        #     )
        self.mapping = pd.get_dummies(self.mapping, columns=["label"])

        if shuffle:
            self.mapping = self.mapping.sample(frac=1)  # shuffle

        self.classes_list = [label.split("_")[1] for label in self.mapping.columns[1:]]

        self.mapping = self.mapping.to_numpy()

        self.classes_count = len(self.mapping[0]) - 1

        self.transform = transforms.Compose([transforms.ToTensor()])

    def __len__(self):
        return len(self.mapping)

    def __getitem__(self, idx):
        img_name = self.mapping[idx, 0]
        img = read_image(os.path.join(self.BASE_PATH, self.image_folder, img_name))

        label = [
            1 if label_class is True else 0 for label_class in self.mapping[idx, 1:]
        ]
        label = np.array(label)

        return img, label

    def translate_encoded_label(self, encoded_label):
        return self.classes_list[list(encoded_label).index(1)]


class CicDdos2019(Dataset):
    BASE_PATH = "C:\VScode_Projects\DP\datasets\CIC-DDoS-2019\clean"
    index: int
    batch_size: int
    classes_count: int
    classes_list: list

    def __init__(
        self,
        shuffle: bool = False,
        mapping_file_name: str = None,
        image_folder_name: str = None,
        binary: bool = False,
    ):
        self.mapping_file = (
            mapping_file_name if mapping_file_name is not None else "labeled_sample.csv"
        )
        self.image_folder = (
            image_folder_name if image_folder_name is not None else "image"
        )
        self.mapping = pd.read_csv(os.path.join(self.BASE_PATH, self.mapping_file))

        if binary:
            self.mapping["label"] = self.mapping["label"].apply(
                lambda x: "normal" if x.lower() == "benign" else "anomaly"
            )
        # else:
        #     self.mapping["label"] = self.mapping["label"].apply(
        #         lambda x: "normal" if x.lower() == "benign" else x.lower()
        #     )
        self.mapping = pd.get_dummies(self.mapping, columns=["label"])

        if shuffle:
            self.mapping = self.mapping.sample(frac=1)  # shuffle

        self.classes_list = [label.split("_")[1] for label in self.mapping.columns[1:]]

        self.mapping = self.mapping.to_numpy()

        self.classes_count = len(self.mapping[0]) - 1

        self.transform = transforms.Compose([transforms.ToTensor()])

    def __len__(self):
        return len(self.mapping)

    def __getitem__(self, idx):
        img_name = self.mapping[idx, 0]
        img = read_image(os.path.join(self.BASE_PATH, self.image_folder, img_name))

        label = [
            1 if label_class is True else 0 for label_class in self.mapping[idx, 1:]
        ]
        label = np.array(label)

        return img, label

    def translate_encoded_label(self, encoded_label):
        return self.classes_list[list(encoded_label).index(1)]