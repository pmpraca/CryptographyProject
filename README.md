# CryptographyProject
 Implementation of applications with 3 algorithms for encrypting and decrypting a message: 2 modern symmetric-key algorithms and 1 asymmetric-key algorithm. The keys used in the implemented algorithms will be generated and stored on disk. The algorithms are the following: DES, AES & RSA

Welcome to Cryptography Project 12/05

Made by: Pedro Praça

Algorithms implemented: AES, DES & RSA.

In order to use the program you just need to run main.c

It has a simple text UI:

How to use UI:

1. From the options given choose 1 to 4. (1-AES, 2-DES, 3-RSA, 4-exit)
2. Choose file you want to encrypt or decrypt by typing the name of it (eg. message.txt)
3. Type 'e' to encrypt or 'd' to decrypt the previous file
4. Choose the name of the output file by typing the name of it (eg. decrypted_message.txt)

Note 1: after step 4 the program goes to step 1 again where you can continue doing encryption or decryption.

Note 2: You only see the files from encrypted or decrypted or even keys being saved after the execution is complete, basicly after you type '4' to exit or you manually stop the execution.

Note 3: The files are saved inside the cmake-build-debug folder. 

Note 4: There's already examples of encrypted, decrypted files for each algorithm, aswell as input_messages ('msg.txt' & 'message.txt')
