import pymongo

# Connect to MongoDB
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["ids"]
packets_collection = db["packets"]
blacklist_collection = db["blacklist"]

def insert_packet(packet_info):
    packets_collection.insert_one(packet_info)

def block_entry(entry):
    ip = entry.get("ip")
    if ip and blacklist_collection.find_one({"ip": ip}) is None:
        blacklist_collection.insert_one({"ip": ip})
