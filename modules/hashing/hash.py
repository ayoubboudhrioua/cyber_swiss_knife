import hashlib
from pathlib import Path



def hash_file(file_path):
    h = hashlib.new("sha256")
    with open(file_path,"rb") as file:
        while True:
            chunk = file.read(1024)
            if chunk == b"":
                break
            h.update(chunk)
    return h.hexdigest()

def verify_integrity(file1,file2):
    hash1 = hash_file(file1)
    hash2 = hash_file(file2)
    print("Checking Integrity between {} and {}" .format(file1,file2))
    if hash1 == hash2 :
        return "File is intact.No modifications have been made."
    return "File has been modified. Possibly unsafe"
        
if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3:
        print("SHA-256 Hash:", hash_file(sys.argv[1]))
        print(verify_integrity(sys.argv[1], sys.argv[2]))
    else:
        print("Usage: python hash.py <file1> <file2>") 
    
    
