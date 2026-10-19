# --- EMBER2024 GOOGLE COLAB TRAINING SCRIPT ---
# Directions:
# 1. Open Google Colab (colab.research.google.com)
# 2. Add a new code cell and paste this entire file in.
# 3. Hit Run. Note: It may take some time to download the dataset.
# 4. Once complete, download "ember_model.txt" and "family_mapping.json" 
#    from the Colab files panel and place them in your local "models" folder.

import os

print("Installing dependencies...")
os.system("git clone https://github.com/FutureComputing4AI/EMBER2024.git")
os.system("cd EMBER2024 && pip install .")
os.system("pip install lightgbm numpy")

import json
import numpy as np
import lightgbm as lgb
import thrember

dataset_path = "/content/ember_dataset"
os.makedirs(dataset_path, exist_ok=True)

# Step 1: Download a smaller slice of PE files (the Challenge split) for demonstration
# so it trains effortlessly without crashing a free Colab instance.
# To train on the FULL dataset later, switch split="challenge" to split="train"
print("Downloading EMBER challenge dataset...")
thrember.download_dataset(dataset_path, file_type="PE", split="challenge")

# Step 2: Vectorize files manually (bypassing thrember library bug for missing train files)
print("Vectorizing features...")
from thrember.model import gather_feature_paths, vectorize_subset

extractor = thrember.PEFeatureExtractor()
feature_paths = gather_feature_paths(dataset_path, "challenge")
nrows = sum([1 for fp in feature_paths for _ in fp.open()])

vectorize_subset(f"{dataset_path}/X_challenge.dat", f"{dataset_path}/y_challenge.dat", feature_paths, extractor, nrows, "label", {})

# For family vectorization, we need to map string labels to ints
from thrember.model import read_label_subset
family_counts = read_label_subset(feature_paths, nrows, "family")
# Assign arbitrary IDs to families for the .dat file (we remap them later down below anyway)
fam_map = {f: i for i, f in enumerate(family_counts.keys())}
vectorize_subset(f"{dataset_path}/X_challenge.dat", f"{dataset_path}/y_family_challenge.dat", feature_paths, extractor, nrows, "family", fam_map)

# Step 3: Read into Arrays
print("Reading features into memory...")
X, y_malicious = thrember.read_vectorized_features(dataset_path, subset="challenge")

# Read family manually from the file we just created using standard np.memmap
y_fam_dat = np.memmap(f"{dataset_path}/y_family_challenge.dat", dtype=np.float32, mode="r")
inv_fam_map = {v: k for k, v in fam_map.items()}

# Convert local integer map back to strings mimicking standard function
y_family = []
for val in y_fam_dat:
    # Safely handle NaN or the default -1 values used by thrember for missing labels
    if np.isnan(val) or val == -1:
        y_family.append("")
    else:
        y_family.append(inv_fam_map.get(int(val), ""))


# Step 4: Map binary + family onto a unified Multi-Class target array
print("Processing Family labels...")

unique_families = np.unique([f for f in y_family if f is not None and f != ""])
family_to_id = {fam: i + 1 for i, fam in enumerate(unique_families)}
family_to_id["Benign"] = 0

# Generic ID for malicious but uncategorized
Generic_Malware_ID = len(family_to_id)
family_to_id["Generic_Malware"] = Generic_Malware_ID

y_combined = np.zeros(len(y_malicious), dtype=int)
for i in range(len(y_combined)):
    if y_malicious[i] == 0:
        y_combined[i] = 0 # Benign
    else:
        fam_str = y_family[i]
        if fam_str in family_to_id:
            y_combined[i] = family_to_id[fam_str]
        else:
            y_combined[i] = Generic_Malware_ID

id_to_family = {v: k for k, v in family_to_id.items()}

# Step 5: Train lightgbm
print("Starting LightGBM Training...")
train_data = lgb.Dataset(X, label=y_combined)

num_classes = len(id_to_family)

params = {
    "objective": "multiclass",
    "num_class": num_classes,
    "metric": "multi_logloss",
    "learning_rate": 0.05,
    "num_leaves": 31,
    "verbose": -1
}

# Fast training rounds for demo
model = lgb.train(params, train_data, num_boost_round=100)

print("Exporting model and mapping...")
model.save_model("ember_model.txt")
with open("family_mapping.json", "w") as f:
    json.dump(id_to_family, f, indent=4)

print("Training finished! The model and JSON file have been saved to Colab.")
