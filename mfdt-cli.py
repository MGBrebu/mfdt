import hashlib
import os
import requests


def hash_file(file_path, algorithm='md5'):
    with open(file_path, 'rb') as f:
        digest = hashlib.file_digest(f, algorithm)
    return digest.hexdigest()

def hash_directory(directory_path, algorithm='md5'):
    hash_values = {}
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = hash_file(file_path, algorithm)
            hash_values[file_path] = file_hash
    return hash_values
            
def check_nsrl_online(hash_value, hash_algorithm='md5'):
    url = f"https://hashlookup.circl.lu/lookup/{hash_algorithm}/{hash_value}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()  # Returns details if the hash is found
    return None

file_path = './test-files/unknown_benign2.docx'
file_hash = hash_file(file_path, 'sha256')
print("File hash:", file_hash)

print("---------------------------------")

directory_path = 'test-files'
for file_path, file_hash in hash_directory(directory_path, 'sha256').items():
    print(file_path, " = ", file_hash)

print("---------------------------------")

file_path = './test-files/Update.exe'
file_hash = hash_file(file_path, 'md5')
print("File hash:", file_hash)
print(check_nsrl_online(file_hash))

file_path = './test-files/Update.exe'
file_hash = hash_file(file_path, 'sha1')
print("File hash:", file_hash)
print(check_nsrl_online(file_hash, 'sha1'))

file_path = './test-files/Update.exe'
file_hash = hash_file(file_path, 'sha256')
print("File hash:", file_hash)
print(check_nsrl_online(file_hash, 'sha256'))