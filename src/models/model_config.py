import torch


class ModelConfig:
    RANDOM_SEED = 42
    BATCH_SIZE = 512
    EPOCHS = 30
    LEARNING_RATE = 1e-3
    PATCH_SIZE = 8
    HEIGHT = 32
    WIDTH = 64
    IN_CHANNELS = 3
    NUM_HEADS = 8
    DROPOUT = 0.1
    ADAM_WEIGHT_DECAY = 0
    ADAM_BETAS = (0.9, 0.999)
    ACTIVATION = "gelu"
    NUM_ENCODERS = 8
    EMBED_DIM = (PATCH_SIZE**2) * IN_CHANNELS  # (8**2)*3=192
    NUM_PATCHES = (HEIGHT // PATCH_SIZE) * (WIDTH // PATCH_SIZE)  # 4*8=32
    NUM_CLASSES = 10
    DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
