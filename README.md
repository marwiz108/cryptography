## Cryptography Application

A simple program that can encrypt plaintext files and decrypt ciphertext files.

The command to encrypt a file:

`python fcrypt.py -e destination_public_key_file sender_private_key_file input_plaintext_file ciphertext_file`

The command to decrypt a file:

`python fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file`


For the encryption, I decided to use a combination of symmetric and asymmetric encryption. I use an AES key for symmetric encryption to encrypt the message, as it is faster for longer files. Then I encrypt the AES key with an asymmetric RSA key. The encrypted AES key gets written in the same file as the ciphertext, as well as the IV used to create the cipher encryptor.

When decrypting, I extract the encrypted AES key and the IV from the top of the file, as we know that the encrypted key is 256 bytes, and the IV is 16 bytes. Then the rest of the file gts read as the ciphertext. I use the RSA private key corresponding to the public key used in encryption, to decrypt the AES key. Then after getting the AES key it is used to decrypt the ciphertext, and the original message gets written to an output file.
