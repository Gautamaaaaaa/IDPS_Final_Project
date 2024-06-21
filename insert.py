import pymongo

# Connect to MongoDB
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["ids"]
blacklist_collection = db["blacklist"]

def add_to_blacklist(url="0", ip="0"):
    # Check if the entry already exists
    if blacklist_collection.find_one({"url": url, "ip": ip}) is None:
        # Insert the entry into the blacklist collection
        blacklist_collection.insert_one({"url": url, "ip": ip})
        print(f"Added to blacklist: URL={url}, IP={ip}")
    else:
        print(f"Entry URL={url}, IP={ip} is already in the blacklist.")

if __name__ == "__main__":
    url_to_blacklist = "DYPUP"  # Replace with the actual URL you want to associate with these IPs

    ip_ranges_to_blacklist = [
        "184.168.99.132"
    ]

    for ip_range in ip_ranges_to_blacklist:
        add_to_blacklist(url=url_to_blacklist, ip=ip_range)

    # Adding a specific URL and IP to blacklist
    specific_url_to_blacklist = "twitter.com"  # Replace with the actual URL
    specific_ip_to_blacklist = "104.244.42.65" # Replace with the actual IP if available
    add_to_blacklist(url=specific_url_to_blacklist, ip=specific_ip_to_blacklist)
    