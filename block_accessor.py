import json
import requests
import getpass
from config import Config

ADDR = "http://127.0.0.1:8800"

def user_login(username, password):
    """Authenticate as regular user"""
    login_url = f"{ADDR}/login"
    resp = requests.post(login_url, data={
        'username': username,
        'password': password
    })
    return resp.status_code == 200

def get_block(block_index):
    """Retrieve specific block by index"""
    chain_url = f"{ADDR}/chain"
    resp = requests.get(chain_url)
    if resp.status_code == 200:
        chain = json.loads(resp.content.decode())
        for block in chain["chain"]:
            if block["index"] == block_index:
                return block
    return None

def print_file_from_block(block_index, filename, username):
    """Print file contents from specific block"""
    password = getpass.getpass(f"Enter password for {username}: ")
    if not user_login(username, password):
        print("Authentication failed")
        return
    
    block = get_block(block_index)
    if not block:
        print(f"Block {block_index} not found")
        return
    
    for trans in block["transactions"]:
        if (trans.get("v_file") == filename and 
            trans.get("owner") == username):
            print(f"\nFile: {filename}")
            print(f"Owner: {trans.get('owner')}")
            print(f"Size: {trans.get('file_size')} bytes")
            print("\nContents:")
            print(trans.get("file_data"))
            return
    
    print(f"File {filename} not found in block {block_index} or you don't have access")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        print("Usage: python block_accessor.py <block_index> <filename> <username>")
        sys.exit(1)
    
    block_index = int(sys.argv[1])
    filename = sys.argv[2]
    username = sys.argv[3]
    print_file_from_block(block_index, filename, username)
