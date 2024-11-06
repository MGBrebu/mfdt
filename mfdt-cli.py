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

def check_virustotal(hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
    return None

#----------------------------------------------

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

print("---------------------------------")

file_path = './test-files/WizTree.exe'
file_hash = hash_file(file_path, 'sha256')
api_key = 'ef395087293e63f72a7838f86ee73431166b2e87fc8d225b1b7a8dcd007b191d'
print(check_virustotal(file_hash, api_key))