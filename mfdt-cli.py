import hashlib
import os
import requests


def hash_file(file_path, algorithm='md5'):
    with open(file_path, 'rb') as f:
        digest = hashlib.file_digest(f, algorithm)
    return digest.hexdigest()

def hash_directory(directory_path, algorithm='md5'):
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = hash_file(file_path, algorithm)
            print(file_path, " = ", file_hash)
            
def check_nsrl_online(hash_value):
    url = f"https://hashlookup.circl.lu/api/hash/{hash_value}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()  # Returns details if the hash is found
    return None

file_path = './test-files/unknown_benign2.docx'
file_hash = hash_file(file_path, 'sha256')
print("File hash:", file_hash)

print("---------------------------------")

directory_path = './test-files'
hash_directory(directory_path, 'sha256')
