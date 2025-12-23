from modules.hash import hash_file,verify_integrity
from modules.encryption import aes_ed,rsa_ed
from modules.passwords import check_strength,hash_pw,verify_password
from getpass import getpass

def menu():
    print("\nSelect operation: ")
    print("1. Hash file")
    print("2. Check file integrity ")
    print("3. AES Encrypt/Decrypt ")
    print("4. RSA Encrypt/Decrypt ")
    print("5. Password Manager ")
    print("0. Exit ")
    
print("""
      Initiating Cryptography toolkit v1.0 ...
                The ultimate Swiss_knife
    \nWelcome, Agent! Your missio, should you choose to accept it:
    - Analyze and hash files to detect tamepering
    - Encrypt and decrypt messages with RSA and AES
    - Securely manage passwords and assess their strength
    
    All systems online. Data protection protocls active.
    Prepare to enter the world of digital secrecy!"""
)
while True :
    menu()
    choice = input("Choice (0-5) : ")
    if choice == "0":
        break
    elif choice == "1":
        file_path = input("Enter file path:")
        print("\nSHA Hash of File is: ", hash_file(file_path))
    elif choice == "2":
        file_path1 = input("Enter file path 1:")
        file_path2 = input("Enter file path 2:")
        print(verify_integrity(file_path1,file_path2))
    elif choice == "3":
        message = input("Enter message: ")
        key , ciphertext,plaintext = aes_ed(message)
        print("AES key: ", key)
        print("AES Ciphertext: ",ciphertext)
        print("AES plaintext: ",plaintext)
    elif choice == "4":
        message = input("Enter message: ")
        ciphertext,plaintext = rsa_ed(message)
        print("RSA message, encrypted with a public key: ", ciphertext)
        print("RSA messagen, decrypted with a private key: ",plaintext)
    elif choice == "5":
        while True:
            password1 = getpass("Enter a password to checck strength: ")
            print(check_strength(password1))
            if check_strength(password1).startswith("Weak"):
                print("Please choose a stronger password.")
            else:
                break
        hashed_password1 = hash_pw(password1)
        print("hashed password: ",hashed_password1)
        attempt = getpass("Re-enter the password to verify: ")
        print(verify_password(attempt,hashed_password1))
    else : 
        print("Invalid choice.")
        
print("Agent, you are exiting your cyber toolkit stay safe and secure")