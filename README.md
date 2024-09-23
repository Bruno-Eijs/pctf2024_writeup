# Packed Full Of Surprises

A walkthrough for a reverse engineering challenge in PatriotCTF 2024.

##### Challenge Description

I encrypted a file with a secret flag, but now I can't seem to figure out how to decrypt it, can you help?

Challenge Author: Txnner   
Link: [https://pctf.competitivecyber.club/](https://pctf.competitivecyber.club/challenges#Packed%20Full%20Of%20Surprises-27)   
Files: flag.txt.enc, encrypt 

### Step 1: Unpacking ELF

We get two files: `flag.txt.enc` is encrypted data and `encrypt` is and ELF file.

From the title of the challenge we might suspect the ELF file is packed. This is then confirmed with `strings`.
```
$ strings encrypt | grep pack
```
which also tells us which packer has been used (UPX)
```
Info: This file is packed with the UPX executable packer http://upx.sf.net 
```
UPX releases can be found on [https://github.com/upx/upx](https://github.com/upx/upx)`.`

Unpack as follows
```
$ /path/to/executable/upx -d encrypt
```
which should give output including `Unpacked 1 file`.

**Note:** The default behavior of UPX is to *replace* the packed file with the unpacked file, while also keeping the name the same.

### Step 2: Decompiling

We load the ELF into Ghidra and get some pretty nicely formatted C code with a `main()` function. The reason it comes out this nice is because the binary was not stripped.

IMAGE 1

### Step 3: Understanding the encryption program

As we would expect from an encryption program, we see two calls to `fopen()`. One for the original `flag.txt` and one for the ciphertext `flag.txt.enc`.

Next we notice a number of function calls that have names that start with `EVP_`. If we google these we see that they belong to the OpenSSL library. If you have a basic familiarity with encryption concepts but want to learn more about OpenSSL [this](https://docs.openssl.org/master/man7/ossl-guide-libcrypto-introduction/) is a good place to start.

Here we will just look at the relevant functions to determine what's going on.

The first function [`EVP_CIPHER_CTX_new()`](https://docs.openssl.org/master/man3/EVP_EncryptInit/#description) creates a so-called **cipher context** which is necessary first step to perform the encryption.

The second [`EVP_aes_256_cfb128()`](https://docs.openssl.org/master/man3/EVP_aes_128_gcm/#return-values) returns an `EVP_CIPHER` structure which contains information about the specific implementation of the encryption algorithm. 

We'll look a bit more closely at the third ['EVP_EncryptInit_ex()'](https://docs.openssl.org/master/man3/EVP_EncryptInit/#description), since it will tell us more about the role of some of the local variables. 

The synopsis declares this function as follows:
```
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
```
The last two arguments are called `key` and `iv`, which are the *encryption key* and *initialization vector* respectively. We then rename these arguments in Ghidra accordingly to see more clearly what values these are.

IMAGE 2, IMAGE 3

The decompiled code in the above image shows a bunch of 8-byte values, but we should note that `EVP_EncryptInit_ex()` does not use them like this. Instead it takes `key` and `iv` as pointers to `unsigned char` arrays. These local variables are all bunched up together on the stack so they become part of the arrays. When we write out decryption program we will define the array properly.

Finally, have a look at [`EVP_EncryptUpdate()`](https://docs.openssl.org/1.1.1/man3/EVP_EncryptInit/#description) which is declared as:
```
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
```
This function performs the encryption, taking blocks of size `inl` at a time from `in`. So `in` points to a buffer for the unencrypted data (that we'll rename `flag_buf`). The encrypted data is stored in `out` (rename `enc_buf`) and its size is pointed to by `outl`. (Note that `inl` and `*outl` don't have to have the same value.)

The last two `EVP_` functions add padding to the ciphertext and free up the allocated memory used by the other functions respectively.

After some more renaming we have a nice template for reversing the decryption program.

Img 4

### Step 4: Decrypting the flag

Now all we need to do is move a few functions around and use the equivalent `Decrypt` functions to the `Encrypt` functions from the OpenSSL library.

We first need to make sure we have the proper libraries.
```
sudo apt install libssl-dev
```
and when compiling our C code we need to use the `-lcrypto` flag. 

Don't forget:
- `#include <openssl/evp.h>` 
- to have `flag.txt.enc` in the same directory as your output binary
- to get the correct byte order for the `iv` and `key` arrays

The following program will do the trick.
```
#include <stdio.h>
#include <openssl/evp.h>

int main()
{
    size_t bytes_read;
    int bytes_read_int;
    int bytes_encrypted;

    unsigned char iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char key[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f};

    unsigned char flag_buf [1024];
    unsigned char enc_buf [1048];

    EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *cipher_context;

    FILE *fp_flag = fopen("flag.txt","wb");
    FILE *fp_enc = fopen("flag.txt.enc","rb");

    cipher_context = EVP_CIPHER_CTX_new();
    cipher = EVP_aes_256_cfb128();
    EVP_DecryptInit_ex(cipher_context, cipher, (ENGINE *)0x0, key, iv);
    while( 1 ) 
    {
        bytes_read = fread(enc_buf, 1, 0x400, fp_enc);
        bytes_read_int = (int)bytes_read;
        if (bytes_read_int < 1)  break;
        EVP_DecryptUpdate(cipher_context, flag_buf, &bytes_encrypted, enc_buf, bytes_read_int);
        fwrite(flag_buf, 1, (size_t)bytes_encrypted, fp_flag);
    }
    EVP_DecryptFinal_ex(cipher_context, flag_buf, &bytes_encrypted);
    fwrite(flag_buf, 1, (size_t)bytes_encrypted, fp_flag);
    EVP_CIPHER_CTX_free(cipher_context);
    fclose(fp_flag);
    fclose(fp_enc);
    return 0;
}
```


