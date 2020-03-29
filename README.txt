Kyle Diodati
CIS 433
Cryptographic Libraries: Security, Implementation, and Performance


--------------------
Installing WolfCrypt
--------------------
navigate to the wolfssl-4.3.0 folder in terminal

run the command below in the terminal:

./configure --enable-openssh --enable-opensslextra --enable-rsa --enable-keygen --enable-rng --enable-ecc --enable-hkdf --enable-eccencrypt --enable-ecccustcurves && make && sudo make install


Wolfcrypt should now be installed with all necessary extras
===========================================================


------------
Making files
------------
navigate to the wolfcrypt_wrapper folder in terminal

run the command below to make all files:

make


all C files should now be executeables
======================================


-------------
Running files
-------------
navigate to the wolfcrypt_wrapper folder in terminal

After running makefile, the following bash commands will execute each file

./rsa_keygen

./rsa_crypto

./ecc_keygen

./ecc_crypto


*note crypto executables require keygen executables to have been run at least one time in order to work*
========================================================================================================
