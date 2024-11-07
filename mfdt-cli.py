import hashlib
import os
import requests

def hash_file(file_path, algorithm='md5'):
    print(f"Calculating '{file_path}'...")
    with open(file_path, 'rb') as f:
        digest = hashlib.file_digest(f, algorithm)
    print(f"File hash calculated: '{digest.hexdigest()}'")
    return digest.hexdigest()

def hash_directory(directory_path, algorithm='md5'):
    print(f"Hashing files in '{directory_path}'...")
    hash_values = {}
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = hash_file(file_path, algorithm)
            hash_values[file_path] = file_hash
    print("# Hashing directory complete")
    return hash_values
            
def check_circl_hashlookup(hash_value, hash_algorithm='md5'):
    print(f"Checking '{hash_value}' on CIRCL hash lookup...")
    url = f"https://hashlookup.circl.lu/lookup/{hash_algorithm}/{hash_value}"
    response = requests.get(url)
    if response.status_code == 200:
        print("Hash lookup complete, file is known")
        return response.json()  # Returns details if the hash is found
    print("Hash lookup complete, file is unknown")
    return None

def check_virustotal(hash, api_key):
    print(f"Checking '{hash}' on VirusTotal...")
    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        print("VirusTotal lookup complete.")
        return data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
    print("VirusTotal lookup failed.")
    return None

def check_directory(directory_path, api_key):
    print(f"-- Beginning malicious file detection on '{directory_path}'...")
    directory_path = 'test-files'
    hash_values = hash_directory(directory_path)
    for file in hash_values:
        print(f"- Checking '{file}'...")
        # Check NSRL
        nsrl_result = check_circl_hashlookup(hash_values[file])
        if nsrl_result:
            print(f"Appending '{file}' as safe")
            report["safe"].append(file)
        else:
            # Check VirusTotal
            virustotal_result = check_virustotal(hash_values[file], api_key)
            if virustotal_result:
                if virustotal_result.get('malicious') > 0:
                    print(f"Appending '{file}' as malicious")
                    report["malicious"].append(file)
                else:
                    print(f"Appending '{file}' as safe")
                    report["safe"].append(file)
            else:
                print(f"Appending '{file}' as unknown")
                report["unknown"].append(file)
    print("# Malicious file detection complete")

def generate_report(report, output_path):
    print(f"-- Generating report")
    with open(output_path, 'w') as f:
        f.write("Malicious File Detection Report\n")
        f.write("="*40 + "\n\n")
        
        f.write("Malicious Files:\n")
        if report["malicious"]:
            for file in report["malicious"]:
                f.write(f" - {file}\n")
        else:
            f.write("None\n")
        f.write("\n")

        f.write("Safe Files:\n")
        if report["safe"]:
            for file in report["safe"]:
                f.write(f" - {file}\n")
        else:
            f.write("None\n")
        f.write("\n")

        f.write("Unknown Files:\n")
        if report["unknown"]:
            for file in report["unknown"]:
                f.write(f" - {file}\n")
        else:
            f.write("None\n")
        f.write("\n")
        
        f.write("="*40 + "\n")
        f.write("End of Report\n")
    print(f"# Report generated at '{output_path}'")

#----------------------------------------------

report = {
    "malicious": [],
    "safe": [],
    "unknown": []
}

check_directory('test-files', 'ef395087293e63f72a7838f86ee73431166b2e87fc8d225b1b7a8dcd007b191d')
generate_report(report, 'reports/report.txt')