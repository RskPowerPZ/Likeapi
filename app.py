from flask import Flask, jsonify
import aiohttp
import asyncio
import json
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)

# ----------------------------
# Encryption/Decryption Helpers
# ----------------------------

# Packet Encryption/Decryption Functions
def encrypt_packet(plain_text):
    """
    Encrypts the given plain text (hex string) using a fixed AES key and IV.
    Returns the cipher text as a hex string.
    """
    plain_text = bytes.fromhex(plain_text)
    key = bytes([101, 116, 33, 120, 72, 83, 97, 119, 82, 94, 37, 56, 74, 50, 83, 53])
    iv = bytes([84, 76, 82, 118, 120, 100, 114, 114, 117, 51, 37, 80, 85, 113, 65, 54])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def decrypt_packet(packet):
    """
    Decrypts the given packet (hex string) using a fixed AES key and IV.
    Returns the decrypted plain text as a hex string.
    """
    packet = bytes.fromhex(packet)
    key = bytes([101, 116, 33, 120, 72, 83, 97, 119, 82, 94, 37, 56, 74, 50, 83, 53])
    iv = bytes([84, 76, 82, 118, 120, 100, 114, 114, 117, 51, 37, 80, 85, 113, 65, 54])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(packet), AES.block_size)
    return plain_text.hex()

# API Encryption/Decryption Functions
def encrypt_api(plain_text):
    """
    Encrypts the given plain text (hex string) using the API key and IV.
    Returns the cipher text as a hex string.
    """
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def decrypt_api(cipher_text):
    """
    Decrypts the given cipher text (hex string) using the API key and IV.
    Returns the decrypted plain text as a hex string.
    """
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(bytes.fromhex(cipher_text)), AES.block_size)
    return plain_text.hex()

# Lookup tables for ID conversion
dec = [ '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f',
        '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f',
        'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af',
        'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf',
        'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf',
        'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df',
        'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef',
        'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']

xxx = [ '1','01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f',
        '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f',
        '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f',
        '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f',
        '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f',
        '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f',
        '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f',
        '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']

def Decrypt_ID(da):
    """
    Decrypts an ID given as a hexadecimal string.
    Supports IDs of length 10 or 8.
    Returns the calculated numeric ID as a string.
    """
    if da is not None and len(da) == 10:
        w = 128
        xxx_len = len(da) / 2 - 1
        xxx_str = str(xxx_len)[:1]
        for i in range(int(xxx_str) - 1):
            w *= 128
        x1 = da[:2]
        x2 = da[2:4]
        x3 = da[4:6]
        x4 = da[6:8]
        x5 = da[8:10]
        return str(w * xxx.index(x5) + (dec.index(x2) * 128) + dec.index(x1) + (dec.index(x3) * 128 * 128) + (dec.index(x4) * 128 * 128 * 128))

    if da is not None and len(da) == 8:
        w = 128
        xxx_len = len(da) / 2 - 1
        xxx_str = str(xxx_len)[:1]
        for i in range(int(xxx_str) - 1):
            w *= 128
        x1 = da[:2]
        x2 = da[2:4]
        x3 = da[4:6]
        x4 = da[6:8]
        return str(w * xxx.index(x4) + (dec.index(x2) * 128) + dec.index(x1) + (dec.index(x3) * 128 * 128))
    
    return None

def Encrypt_ID(x):
    """
    Encrypts a numeric ID into its hexadecimal string representation.
    This function uses the lookup tables 'dec' and 'xxx' defined above.
    """
    x = int(x)
    x = x / 128 
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                strx = int(x)
                y = (x - int(x)) * 128
                z = (y - int(y)) * 128
                n = (z - int(z)) * 128
                m = (n - int(n)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                strx = int(x)
                y = (x - int(x)) * 128
                z = (y - int(y)) * 128
                n = (z - int(z)) * 128
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
    x_int = int(x)
    if x_int == 0:
        y = (x - int(x)) * 128
        return xxx[int(y)]
    else:
        y = (x - int(x)) * 128
        return dec[int(y)] + xxx[int(x)]

def Encrypt(x):
    """
    Alternative encryption for a numeric ID.
    Similar in purpose to Encrypt_ID.
    """
    x = int(x)
    x = x / 128 
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                strx = int(x)
                y = (x - int(x)) * 128
                z = (y - int(y)) * 128
                n = (z - int(z)) * 128
                m = (n - int(n)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                strx = int(x)
                y = (x - int(x)) * 128
                z = (y - int(y)) * 128
                n = (z - int(z)) * 128
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
        else:
            strx = int(x)
            y = (x - int(x)) * 128
            z = (y - int(y)) * 128
            return dec[int(z)] + dec[int(y)] + xxx[int(x)]
    else:
        strx = int(x)
        if strx == 0:
            y = (x - int(x)) * 128
            return xxx[int(y)]
        else:
            y = (x - int(x)) * 128
            return dec[int(y)] + xxx[int(x)]

# ----------------------------
# Application Logic & Routes
# ----------------------------

# Load tokens from token_ind.json
def load_tokens_from_file(filepath="token_ind.json"):
    if not os.path.exists(filepath):
        print(f"⚠️ File not found: {filepath}")
        return []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            tokens_data = json.load(f)
            print("🔹 Loaded data from file:", tokens_data)
            # Assuming the file contains a list of dictionaries with a "token" key
            tokens = [item.get("token") for item in tokens_data if item.get("token")]
            # Filter out any invalid tokens like "N/A" and take first 4 tokens only
            valid_tokens = [t for t in tokens if t and t != "N/A"][:25]
            print(f"✅ Extracted {len(valid_tokens)} valid tokens: {valid_tokens}")
            return valid_tokens
    except Exception as e:
        print(f"⚠️ Error loading tokens: {e}")
        return []

# Sending the requests concurrently
async def visit(session, token, uid, data):
    # Updated URL and Host header for freefiremobile.com
    url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    headers = {
        "ReleaseVersion": "OB48",
        "X-GA": "v1 1",
        "Authorization": f"Bearer {token}",
        "Host": "client.ind.freefiremobile.com"
    }
    try:
        async with session.post(url, headers=headers, data=data, ssl=False):
            pass  # ignoring the response
    except Exception as e:
        # Optionally log error if needed
        pass

async def send_requests_concurrently(tokens, uid, num_requests=1000):
    connector = aiohttp.TCPConnector(limit=0)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Prepare the data payload by encrypting the API packet
        data = bytes.fromhex(encrypt_api("08" + Encrypt_ID(uid) + "1801"))
        tasks = [asyncio.create_task(visit(session, tokens[i % len(tokens)], uid, data))
                 for i in range(num_requests)]
        await asyncio.gather(*tasks)

@app.route('/<int:uid>', methods=['GET'])
def send_visits(uid):
    tokens = load_tokens_from_file()
    
    if not tokens:
        return jsonify({"message": "⚠️ No valid tokens found"}), 500
    
    print(f"✅ Number of available tokens: {len(tokens)}")
    num_requests = 1000
    asyncio.run(send_requests_concurrently(tokens, uid, num_requests))
    
    return jsonify({"message": f"✅ Sent {num_requests} visits to UID: {uid} using {len(tokens)} tokens at high speed"}), 200

# ----------------------------
# Testing Encryption/Decryption (Optional)
# ----------------------------
if __name__ == "__main__":
    # Optional testing of decryption functions:
    print("Decrypted API packet:", decrypt_api('b7471b47b8758becad829ca929e3de29'))
    print("Encrypted ID for 270279853:", Encrypt_ID(270279853))
    
    # Start the Flask app
    app.run(host="0.0.0.0", port=5000)