class BaseConfig:
    HEIGHT: int
    WIDTH: int
    SIZE: int
    PATH: str
    INPUT_FILE_NAME: str
    OUTPUT_CSV_FILE: str
    IMG_FILE_NAME_TEMPLATE: str


class CICIDS2017_Config(BaseConfig):
    HEIGHT = 32
    WIDTH = 64
    SIZE = HEIGHT * WIDTH
    PATH = "..\..\datasets\CIC-IDS-2017"
    INPUT_FILE_NAME = PATH + "\CICIDS_converted_data.csv"
    OUTPUT_CSV_FILE = PATH + "\cicids2017_img.csv"
    IMG_FILE_NAME_TEMPLATE = "cic_ids_2017_{idx}.png"


class CICIDS2017_SERIALIZED_Config(BaseConfig):
    HEIGHT = 64
    WIDTH = 128
    SIZE = HEIGHT * WIDTH
    PATH = "..\..\datasets\CIC-IDS-2017"
    INPUT_FILE_NAME = PATH + "\CICIDS_converted_data.csv"
    OUTPUT_CSV_FILE = PATH + "\cicids2017_img_serialized_5.csv"
    IMG_FILE_NAME_TEMPLATE = "cic_ids_2017_{idx}.png"


class UNSWNB15_Config(BaseConfig):
    HEIGHT = 32
    WIDTH = 64
    SIZE = HEIGHT * WIDTH
    PATH = "..\..\datasets\UNSW_NB15"
    INPUT_FILE_NAME = PATH + "\UNSW_converted_data.csv"
    OUTPUT_CSV_FILE = PATH + "\unswnb15_img.csv"
    IMG_FILE_NAME_TEMPLATE = "unswnb15_{idx}.png"


class UNSWNB15_SERIALIZED_Config(BaseConfig):
    HEIGHT = 64
    WIDTH = 128
    SIZE = HEIGHT * WIDTH
    PATH = "..\..\datasets\UNSW_NB15"
    INPUT_FILE_NAME = PATH + "\UNSW_converted_data.csv"
    OUTPUT_CSV_FILE = PATH + "\unswnb15_img_serialized_5.csv"
    IMG_FILE_NAME_TEMPLATE = "unswnb15_{idx}.png"


if __name__ == "__main__":
    test = CICIDS2017_Config()
    print(test.IMG_FILE_NAME_TEMPLATE.format(idx="50"))
