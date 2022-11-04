import os
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes


def encrypt(dest_pubkey_fn, sender_privkey_fn, input_pt_fn, ciphertext_fn):
    '''
        This method is used to encrypt a plaintext message to send to a destination.
        Create a symmetric AES key, then encrypt the AES key with the RSA public key.
        Encrypt the plaintext with the AES key, then write the ciphertext to its file.
    '''
    # python fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file
    print("encrypting...\n")

    # check for correct key file format
    public_key_format = dest_pubkey_fn.split(".")[-1]
    private_key_format = sender_privkey_fn.split(".")[-1]

    if (public_key_format not in ["pem", "der"]):
        print("Destination public key file format is incorrect.\n")
        sys.exit()
    if (private_key_format not in ["pem", "der"]):
        print("Sender private key file format is incorrect.\n")
        sys.exit()

    # get destination RSA public key
    with open(dest_pubkey_fn, "rb") as pubkey_f:
        if public_key_format == "pem":
            dest_pubkey = serialization.load_pem_public_key(
                pubkey_f.read(),
                backend=default_backend()
            )
        elif public_key_format == "der":
            dest_pubkey = serialization.load_der_public_key(
                pubkey_f.read(),
                backend=default_backend()
            )

    # generate symmetric AES key
    aeskey = os.urandom(16)
    iv = os.urandom(16)
    aescipher = Cipher(algorithms.AES(aeskey), modes.CTR(iv), backend=default_backend())
    encryptor = aescipher.encryptor()

    # encrypt AES key with RSA public key
    e_aeskey = dest_pubkey.encrypt(
        aeskey,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )

    ciphertext = b''
    # encrypt plaintext message with AES encryptor
    with open(input_pt_fn, "r") as input_f:
        line = input_f.readline()
        print(line.encode())
        ciphertext += encryptor.update(line.encode())
    ciphertext += encryptor.finalize()

    # write encrypted AES key & ciphertext to file
    with open(ciphertext_fn, "wb") as output_f:
        output_f.write(e_aeskey)
        output_f.write(iv)
        output_f.write(ciphertext)

def decrypt(dest_privkey_fn, sender_pubkey_fn, ciphertext_fn, output_pt_fn):
    '''
        This method is used to decrypt a secret message into plaintext.
        Get the encryptes AES key and IV from the ciphertext file.
        Decrypt the AES key with the RSA private key.
        Decrypt the ciphertext using the decryptes AES key, and write the plaintext to its file.
    '''
    # python fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file
    print("decrypting...\n")

    # check for correct key file format
    private_key_format = dest_privkey_fn.split(".")[-1]
    public_key_format = sender_pubkey_fn.split(".")[-1]

    if (private_key_format not in ["pem", "der"]):
        print("Destination private key file format is incorrect.\n")
        sys.exit()
    if (public_key_format not in ["pem", "der"]):
        print("Sender public key file format is incorrect.\n")
        sys.exit()

    # get destination RSA private key
    with open(dest_privkey_fn, "rb") as privkey_f:
        if private_key_format == "pem":
            private_key = serialization.load_pem_private_key(
                privkey_f.read(),
                password=None,
                backend=default_backend()
            )
        elif private_key_format == "der":
            private_key = serialization.load_der_private_key(
                privkey_f.read(),
                password=None,
                backend=default_backend()
            )

    # get encrypted AES key and ciphertext
    with open(ciphertext_fn, "rb") as cipher_f:
        e_aeskey = cipher_f.read(256)
        iv = cipher_f.read(16)
        ciphertext = cipher_f.read()
    print(f"HERE\n{ciphertext}\n\n")

    # decrypt encrypted AES key with RSA private key
    aeskey = private_key.decrypt(
        e_aeskey,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )

    # create decryptor cipher
    aescipher = Cipher(algorithms.AES(aeskey), modes.CTR(iv), backend=default_backend())
    decryptor = aescipher.decryptor()

    # decrypt ciphertext with AES key
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    print(f"Secret Message: {plaintext.decode()}")

    with open(output_pt_fn, "w") as output_f:
        output_f.write(plaintext.decode())

def main():
    method = sys.argv[1]
    if method == "-e":
        encrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    elif method == "-d":
        decrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])

if __name__ == "__main__":
    main()
