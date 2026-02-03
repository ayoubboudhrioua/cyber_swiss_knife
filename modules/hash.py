import hashlib

#text = "Hello World!"
#hash_object = hashlib.sha256(text.encode())
#hash_digest = hash_object.hexdigest()
#print("SHA hash of: ",text," is ",hash_digest)

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
    print("checking Integrirty between {} and {}" .format(file1,file2))
    if hash1 == hash2 :
        return "File is intact.No modifications have been made."
    return "File has been modified. Possibly unsafe"
        
if __name__ == "__main__":
    print("SHA Hash of file of is: ",hash_file("myenv\\sample_files\\sample.txt"))
    print(verify_integrity("myenv\\sample_files\\sample.txt","myenv\\sample_files\\sample2.txt")) # the sample2 file is a just the same  with a few extra spaces 
    
    
