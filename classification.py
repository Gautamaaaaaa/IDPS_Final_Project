import pickle

# Load the trained model
with open("model\\best_model.pkl", "rb") as model_file:
    best_clf = pickle.load(model_file)

def classify_packet(packet_info):
    from preprocessing import preprocess_packet
    X = preprocess_packet(packet_info)
    prediction = best_clf.predict(X)
    return prediction[0]
