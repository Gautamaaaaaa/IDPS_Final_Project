from flask import Flask, render_template, jsonify, request
from pymongo import MongoClient

app = Flask(__name__)

client = MongoClient('mongodb://localhost:27017/')
db = client['ids']
blacklist_collection = db['blacklist']

def block_entry(entry):
    ip = entry.get("ip")
    if ip and blacklist_collection.find_one({"ip": ip}) is None:
        blacklist_collection.insert_one({"ip": ip})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/data')
def data():
    num_entries = int(request.args.get('num_entries', 50))
    packets = list(db.packets.find({}, {'_id': 0}).sort('_id', -1).limit(num_entries))
    blacklist = list(db.blacklist.find({}, {'_id': 0}))
    
    blacklist_ips = [b.get('ip') for b in blacklist]
    
    for packet in packets:
        src_ip = packet.get('src')
        if src_ip:
            packet['status'] = 'Dangerous' if src_ip in blacklist_ips else 'Normal'
        else:
            packet['status'] = 'Unknown'

    return jsonify({'packets': packets, 'blacklist': blacklist})

if __name__ == '__main__':
    app.run(debug=True)
