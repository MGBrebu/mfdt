import hashlib
import os

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

file_path = './test-files/unknown_benign2.docx'
file_hash = hash_file(file_path, 'sha256')
print("File hash:", file_hash)

print("---------------------------------")

directory_path = './test-files'
hash_directory(directory_path, 'sha256')
