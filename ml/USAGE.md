# Device Type Classifier (Offline ML Pipeline)

Developed by **Makhosi Andile Surge**, this project provides a **machine learning pipeline** for classifying networked devices (e.g., Camera, PC, Router, Phone, Alexa) from scan data.

It is designed to work **fully offline** — no external APIs or servers required.

---

## 📂 Project Layout

```
/ml/
 ├── features.py         # Extract ML-friendly features from raw scan JSON/dicts
 ├── train.py            # Train the classifier on a dataset
 ├── predict.py          # Predict device type from scan data
 ├── ml_integration.py   # Connects scanner engine (main.py) with ML classifier
 ├── model.pkl           # Saved trained model (generated after training)
 ├── sample_dataset.csv  # Example dataset for training
 └── README.md           # Project documentation
```

---

## ⚙️ Requirements

Install dependencies locally (Python 3.8+ recommended):

```bash
pip install pandas numpy scikit-learn xgboost joblib
```

---

## 📊 Dataset Format

The training dataset must contain a **label column** `device_type` and either:

1. **Raw scans** (as JSON strings) in a `raw_scan` column.
   Example row:

   ```csv
   raw_scan,device_type
   '{"open_ports":[{"port":80,"proto":"tcp","service":"http"},{"port":554,"proto":"tcp","service":"rtsp"}],"ttl":64,"mac_vendor":"Hikvision"}',Camera
   ```

2. **Pre-extracted features** (as produced by `features.extract_features()`), plus the `device_type` column.

An example dataset (`sample_dataset.csv`) is included.

---

## 🧩 Feature Extraction (`features.py`)

Given raw scan results (JSON or dict), the feature extractor computes:

* **Port features**

  * Number of open ports, TCP/UDP counts
  * Presence of specific ports (22, 23, 53, 80, 443, 554, 8080, 8443, 1900, …)
  * Service counts (http, https, ssh, telnet, dns, smb, rdp, vnc, mqtt, coap, …)
  * Port min/max/mean

* **Protocol toggles**

  * `has_upnp`, `has_ssdp`, `has_dhcp`

* **Device metadata**

  * TTL value
  * OS guess (`linux`, `windows`, `android`, …)
  * Normalized MAC vendor

* **Keyword flags**

  * Hits from banners/services/hostnames (rtsp, telnet, ssh, hikvision, tplink, apple, samsung, …)

**Output:** a single-row pandas DataFrame ready for ML.

---

## 🏋️ Training (`train.py`)

Train the classifier:

```bash
python train.py --csv sample_dataset.csv --out model.pkl
```

✔ Loads dataset (`.csv`)
✔ Expands raw scans (if present) into features
✔ Splits into train/test (80/20)
✔ Builds a **scikit-learn Pipeline**:

* Imputation for missing values
* OneHot encoding for categorical values
* Model: **XGBoost** (if available), else **RandomForest**
  ✔ Prints accuracy, classification report, and top-20 feature importances
  ✔ Saves trained pipeline to `model.pkl`

---

## 🔮 Prediction (`predict.py`)

Run predictions offline:

```bash
python predict.py --model model.pkl --json '{"open_ports":[{"port":80,"proto":"tcp","service":"http"},{"port":554,"proto":"tcp","service":"rtsp"}],"ttl":64,"mac_vendor":"Hikvision"}'
```

Example output:

```
Device: Camera
Confidence: 0.97
```

You can also pass a path to a `.json` file:

```bash
python predict.py --model model.pkl --json new_scan.json
```

---

## 🔗 Integration with Scanner (`ml_integration.py`)

I (Manman) also developed **`ml_integration.py`** to connect the classifier directly to the existing network scanner (`main.py`).

To run a **full scan with automatic device classification**:

```bash
python ml/ml_integration.py
```

This will:

1. Run the network scanner (`main.py`)
2. Extract scan data into ML features
3. Predict device type for each host
4. Print results like:

```
================================================================================
MACHINE LEARNING DEVICE CLASSIFICATION
================================================================================
[ML] 192.168.1.10   -> Camera     (confidence: 0.93)
```

---

## 🚀 Example Workflow

1. **Train on included dataset:**

   ```bash
   python train.py --csv sample_dataset.csv --out model.pkl
   ```

2. **Predict on a new scan (standalone ML):**

   ```bash
   python predict.py --model model.pkl --json '{"open_ports":[{"port":22,"proto":"tcp","service":"ssh"},{"port":443,"proto":"tcp","service":"https"}],"ttl":64,"mac_vendor":"Dell","os":"Windows"}'
   ```

   Output:

   ```
   Device: PC
   Confidence: 0.91
   ```

3. **Run scanner + classification in one step:**

   ```bash
   python ml/ml_integration.py
   ```

---

## 🛠️ Extending the Project

* **Add more vendors/keywords:** edit `BANNER_KEYWORDS` or `_normalize_vendor()` in `features.py`.
* **Expand dataset:** capture real scans (e.g., from Nmap), store them as JSON in a `raw_scan` column with correct labels.
* **Try different models:** edit `build_pipeline()` in `train.py` (SVM, LightGBM, etc.).
* **Integrate in tools:** the saved `model.pkl` is a drop-in for Python apps (`joblib.load()`).

---

## 📌 Notes

* Works **fully offline** — all logic is self-contained.
* The included dataset is **synthetic**; for real-world use, retrain with real scan data.
* The pipeline is modular: feature extraction, training, prediction, and scanner integration are clearly separated.

---

## 📄 License

MIT License — feel free to use, modify, and integrate into your projects.
