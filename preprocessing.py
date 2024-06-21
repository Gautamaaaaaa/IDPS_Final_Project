import pandas as pd
import pickle
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Load preprocessing tools
with open("model\\encoder.pkl", "rb") as encoder_file:
    encoder = pickle.load(encoder_file)

with open("model\\scaler.pkl", "rb") as scaler_file:
    scaler = pickle.load(scaler_file)

cat_columns = ["proto", "service", "state"]

def preprocess_packet(packet_info):
    from feature_extraction import extract_features
    features = extract_features(packet_info)
    df = pd.DataFrame([features])
    for col in cat_columns:
        if col in df.columns:
            try:
                df[col] = encoder.transform(df[col])
            except ValueError:
                df[col] = -1  # Assign a default value for unseen categories
        else:
            df[col] = -1  # Assign a default value for unseen categories

    # Ensure all expected features are present
    expected_features = [
        "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl",
        "dttl", "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit", "swin",
        "stcpb", "dtcpb", "dwin", "tcprtt", "synack", "ackdat", "smean", "dmean", "trans_depth",
        "response_body_len", "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm",
        "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd",
        "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports"
    ]
    for feature in expected_features:
        if feature not in df.columns:
            df[feature] = 0  # Assign default value if the feature is missing

    # Ensure the order of columns matches the expected order
    df = df[expected_features]

    X = scaler.transform(df)
    return X
