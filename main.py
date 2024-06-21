from packet_handler import start_sniffing
from pymongo import MongoClient
import subprocess


# Define the functions to fetch blacklisted IPs and block them
def fetch_blacklisted_ips():
    # Replace the following with your actual MongoDB connection string
    client = MongoClient('mongodb://localhost:27017/')
    db = client['ids']
    collection = db['blacklist']
    
    # Fetch all unique IP addresses from the collection
    ips = collection.distinct('ip')
    return ips

def block_ips(ips):
    # Convert the list of IPs to a comma-separated string
    ip_list = ','.join(ips)
    command = f'netsh advfirewall firewall add rule name="Block Blacklisted IPs" remoteip={ip_list} dir=out enable=yes action=block'
    
    # Run the command using subprocess
    try:
        subprocess.run(command, shell=True, check=True)
        print(f'Successfully blocked IPs: {ip_list}')
    except subprocess.CalledProcessError as e:
        print(f'Error occurred: {e}')
def main():
    ips = fetch_blacklisted_ips()
    block_ips(ips)
    print("Starting IDS...")
    start_sniffing()

if __name__ == "__main__":
    main()