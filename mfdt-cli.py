import hashlib
import os
import requests
import datetime
import argparse

# Hashes a single file given a file path and hash algorithm, defaults to MD5, returns file's hash value
def hash_file(file_path, algorithm='md5'):
    print(f"Calculating '{file_path}'...")
    with open(file_path, 'rb') as f:
        digest = hashlib.file_digest(f, algorithm)
    print(f"File hash calculated: '{digest.hexdigest()}'")
    return digest.hexdigest()

# Hashes multiple files given a directory path and hash algorithm, defaults to MD5, returns dictionary of file paths and hash values
# Calls hash_file() for each file in the directory
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
           
# Checks a hash value on CIRCL hash lookup service, returns the result if the hash is known, otherwise returns None
def check_circl_hashlookup(hash_value, hash_algorithm='md5'):
    print(f"Checking '{hash_value}' on CIRCL hash lookup...")
    url = f"https://hashlookup.circl.lu/lookup/{hash_algorithm}/{hash_value}"
    response = requests.get(url)
    if response.status_code == 200:
        print("Hash lookup complete, file is known")
        return response.json()
    print("Hash lookup complete, file is unknown")
    return None

# Checks a hash value on VirusTotal, returns the result if the check is successful, otherwise returns None
# NB: Does not check if the file is safe, simply returns the full response
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

# Classifies a file as malicious, safe, or unknown given a file path, hash value, and API key for VirusTotal
# Returns the classification and a dictionary of file details including file path, hash, CIRCL result, and VirusTotal result and link
def classify_file(file_path, hash, api_key):
    file_details = {
            "file": file_path,
            "hash": hash,
            "circl": None,
            "virustotal": "N/A"
    }
    classification = None
    
    circl_result = check_circl_hashlookup(hash)
    if circl_result:
        print(circl_result)
        classification = "Safe"
        file_details['circl'] = "Known"
    else:
        file_details['circl'] = "Unknown"
        vt_result = check_virustotal(hash, api_key)
        if vt_result:
            if vt_result.get('malicious', 0) > 0:
                classification = "Malicious"
                file_details['virustotal'] = "Malicious, " + f"https://www.virustotal.com/gui/file/{hash}/detection"
            else:
                classification = "Safe"
                file_details['virustotal'] = "Safe, " + f"https://www.virustotal.com/gui/file/{hash}/detection"
        else:
            classification = "Unknown"
            file_details['virustotal'] = "Unknown, " + f"https://www.virustotal.com/gui/file/{hash}/detection"

    return classification, file_details

# Uses classify_file() to classify all files in a directory given a directory path and an API key for VirusTotal
# Returns a report dictionary with lists of malicious, safe, and unknown files and their details
def classify_directory(directory_path, api_key):
    report = {
        "malicious": [
        ],
        "safe": [
        ],
        "unknown": [
        ]
    }
    hash_values = hash_directory(directory_path)
    for file_path, hash in hash_values.items():
        classification, file_details = classify_file(file_path, hash, api_key)
        report[classification.lower()].append(file_details)
    return report

# Generates a report textfile given a report dictionary and a directory path to save the report
def generate_report(report, report_dir):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
    with open(f"{report_dir}/report_{timestamp}.txt", 'w') as f:
        f.write(f"Total malicious files: {len(report['malicious'])}\n")
        f.write(f"Total safe files: {len(report['safe'])}\n")
        f.write(f"Total unknown files: {len(report['unknown'])}\n")
        for classification, files in report.items():
            f.write("========================================\n")
            f.write(f"{classification.capitalize()} files:\n")
            for file in files:
                f.write(f"\tFile: {file['file']}\n")
                f.write(f"\t\tHash: {file['hash']}\n")
                f.write(f"\t\tCIRCL: {file['circl']}\n")
                f.write(f"\t\tVirusTotal: {file['virustotal']}\n")
            f.write("\n")

def main():
    parser = argparse.ArgumentParser(description="Malicious File Detection Tool")
    
    parser.add_argument('--scan-dir', '-d', required=True, default='./test-files', help='Directory to scan')
    parser.add_argument('--api-key', '-k', required=True, help='VirusTotal API Key')
    parser.add_argument('--report-dir', '-r', default='./reports', help='Directory to save the report')

    args = parser.parse_args()

    scan_dir = args.scan_dir
    report_dir = args.report_dir
    api_key = args.api_key

    report_dict = classify_directory(scan_dir, api_key)
    generate_report(report_dict, report_dir)

if __name__ == "__main__":
    main()
