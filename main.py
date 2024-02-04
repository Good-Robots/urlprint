from utils.loader import DataLoader

SOURCE = "https://ennys.s3.eu-north-1.amazonaws.com/urls.json"
DATA_DIR = "data"
LABELS_FILE = f"{DATA_DIR}/labels.txt"
FEATURES_FILE = f"{DATA_DIR}/features.csv"

dl = DataLoader(source=SOURCE, data_dir=DATA_DIR, labels_file=LABELS_FILE)
dl.write_headers()
features = dl.load_features()


for i in features:
    with open(FEATURES_FILE, "a") as f:
        line = ",".join([str(v) for v in i.values()])
        f.write(line + "\n")