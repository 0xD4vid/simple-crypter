#!/usr/bin/python3
# Creates three byte objects, that are base64 encoded. shellcode, key and IV.
# AES code taken from: https://www.suls.co.uk/slae-assignment-7-custom-crypter/
# Dycrypt in C# (https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=net-6.0)


# pip3 install pycryptodome
import optparse
import base64
import subprocess
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


# Colours
Red = "\u001b[31m"
Green = "\u001b[32m"
Yellow = "\u001b[33m"
Blue = "\u001b[34m"
Magenta = "\u001b[35m"
Cyan = "\u001b[36m"
Reset = "\u001b[0m"
Red_Background = "\u001b[41;1m"
Bold = "\u001b[1m"


# If using msfvenom, this runs the msfvenom command and gets hex string output.
def shell_create(command):
    print(f"{Green}{Bold}[>] msfvenom command is running....{Reset}")
    # msfvenom command.
    cmd = f"{command}"
    output = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # cba with this error search, so if there's no output, then there's an error.
    if len(output.stdout) == 0:
        stderr = output.stderr.decode('utf-8')
        print(f"{Red_Background}[msfvenom Syntax Error]{Reset}\n{stderr}")
        exit()
    else:
        return output.stdout


# Creation of key, IV. Then calls cipher_create function. 
def aes_encrypt_shellcode(data):
    print(f"{Green}{Bold}[>] Encrypting Shellcode!{Reset}")

    IV = get_random_bytes(16)
    key = get_random_bytes(16)

    padded = pad(data,16)
    # Call cipher_create function
    encrypted_data = cipher_create(key,padded,IV)
    # Call base64_encode. 'encrypted_data' is converted to bytes inside C# app
    base64_encode(encrypted_data, IV, key)


# Creates cipher, uses cipher to encrypt data. returns said data.
def cipher_create(key,shellcode,IV):
    # cipher creation
    cipher = AES.new(key,AES.MODE_CBC, IV)
    # Encrypts with the newly created cipher.
    return cipher.encrypt(shellcode)


# Encode the data we created. To be used with our C# executable.
def base64_encode(encrypted_data, IV=False, key=False):

    if IV and key:
        print(f"{Green}{Bold}[>] Shellcode Encrypted!{Reset}")
        print(f"{Green}{Bold}[>] Base64 Encoded Payloads created!{Reset}")
        # IV
        encoded_iv = base64.b64encode(IV)
        print(f"{Cyan}{Bold}[>] IV:{Reset} {encoded_iv.decode(('utf-8'))}")
        # KEY
        encoded_key = base64.b64encode(key)
        print(f"{Cyan}{Bold}[>] KEY:{Reset} {encoded_key.decode(('utf-8'))}")
        # Shellcode
        encoded = base64.b64encode(encrypted_data)
        print(f"{Cyan}{Bold}[>] Shellcode:{Reset} {encoded.decode('utf-8')}")


if __name__ == "__main__":

    try:
        sys.argv[1]
    except:
        print(f"{Red}{Bold}[!] Requires one argument.{Reset}")
        print("Help: python3 crypter.py -h")
        exit()

    
    parser = optparse.OptionParser(usage='%prog -m msfvenom "command" -f hex\nUsage: %prog -H "hex string"')
    parser.add_option('-H', dest='hex_string', type='string', help='Raw hex string format')
    parser.add_option('-m', dest='msf_command', type='string', help='Enter the msfvenom command usin -f/--format hex')

    (options, args) = parser.parse_args()

    hex_string = str(options.hex_string)
    msf_command = str(options.msf_command)

    if hex_string != "None":
        data =  hex_string.encode()

    if msf_command != "None":
        data = shell_create(msf_command)

    # Call function and pass the shellcode as bytes.
    aes_encrypt_shellcode(data)
    
    # print(f"\n{Yellow}{Bold}C# Example:{Reset}")
    # print(f"{Yellow}{Bold}C# Aes Decryption:{Reset} (https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=net-6.0)")
    # print(f"\nOnce decoded and decrypted, we add the following code to a byte array.")
    # print("""
    #         // Create byte array, half size of decrypted data
    #         byte[] shellCode = new byte[plaintext.Length / 2];

    #         var res = new List<string>();
    #         for (int i = 0; i < plaintext.Length; i += 2)
    #             res.Add(plaintext.Substring(i, 2));

    #         for (int i = 0; i < shellCode.Length; i++)
    #         {
    #             shellCode[i] = Convert.ToByte(res[i], 16);
    #         }    
    # """)

    print(f"\n{Yellow}{Bold}Goodbye......{Reset}")
