import hashlib
import sys
from pwn import log
from concurrent.futures import ThreadPoolExecutor

# Function to compute the hash of a given input based on the specified algorithm
def compute_hash(password, algorithm):
    if algorithm.lower() == 'sha256':
        return hashlib.sha256(password).hexdigest()
    elif algorithm.lower() == 'sha1':
        return hashlib.sha1(password).hexdigest()
    elif algorithm.lower() == 'md5':
        return hashlib.md5(password).hexdigest()
    else:
        raise ValueError("Unsupported hash algorithm. Supported algorithms: sha256, sha1, md5.")

# Function to attempt password recovery
def attempt_password(password, wanted_hash, algorithm):
    global attempts, found
    password = password.strip("\n").encode('latin-1')
    password_hash = compute_hash(password, algorithm)

    with lock:
        attempts += 1
        p.status(f"[Attempt {attempts}] Trying: {password.decode('latin-1')} => {password_hash}")

    if password_hash == wanted_hash:
        with lock:
            found = True
            p.success(f"Password found after {attempts} attempts: '{password.decode('latin-1')}' (Hash: {wanted_hash})")
            log_results(f"Success: Password '{password.decode('latin-1')}' found for hash {wanted_hash} in {attempts} attempts.\n")
            sys.exit(0)

# Function to log results to a file
def log_results(message):
    with open("hash_crack_results.txt", "a") as log_file:
        log_file.write(message)

# Main function
if __name__ == "__main__":
    # Check if the right number of arguments is provided
    if len(sys.argv) != 4:
        print("Invalid arguments!")
        print(f"Usage: {sys.argv[0]} <sha256sum> <algorithm> <wordlist>")
        sys.exit(1)

    # Initialize variables
    wanted_hash = sys.argv[1]
    algorithm = sys.argv[2]
    password_file = sys.argv[3]
    attempts = 0
    found = False
    lock = threading.Lock()

    # Start the hash cracking process
    with log.progress(f"Attempting to recover the password for: {wanted_hash}") as p:
        try:
            with open(password_file, "r", encoding="latin-1") as password_list:
                with ThreadPoolExecutor(max_workers=8) as executor:
                    # Submit tasks to the thread pool
                    futures = [executor.submit(attempt_password, password, wanted_hash, algorithm) for password in password_list]

                    # Wait for all threads to complete
                    for future in futures:
                        future.result()
            
            # If no match is found
            if not found:
                p.failure("Password hash not found in the wordlist!")
                log_results(f"Failure: No password found for hash {wanted_hash}.\n")

        except FileNotFoundError:
            print(f"Error: Password file '{password_file}' not found.")
        except ValueError as ve:
            print(ve)
        except Exception as e:
            print(f"An error occurred: {e}")
