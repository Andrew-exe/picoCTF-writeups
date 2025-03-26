We are given the room description:

**The imposter was able to fool us last time, so we've strengthened our defenses!
Here's our [list](https://challenge-files.picoctf.net/c_verbal_sleep/5eaec7881c3f1aa05cff2820457d324096dd7de33fc492a84ba08cd67aba1bf1/cheese_list.txt)of cheeses.
Connect to the program on our server: `nc verbal-sleep.picoctf.net 54455`**

and three hints:

1. **I heard that _SHA-256_ is the best hash function out there!**
2. **Remember Squeexy, we enjoy our cheese with exactly _2 nibbles_ of _hexadecimal-character salt_!**
3. **Ever heard of _rainbow tables_?**

The list of cheeses that was given was a text file with names of known cheese. 
Connecting to the program we see 

![[Pasted image 20250324205156.png]]

We are prompted to guess the correct cheese from the cheese_list.txt file they gave us so that it matches the encrypted cheese: `625c5bcd5f0781cfa21a27658ce36132c7c19c148dab558e9f66a8e7a4fef95b`

We know that is is SHA-256 encrypted, however hint 2 suggests that there is a 2 nibble or 1 byte hexademical-character salt. 

At first, we created numerous rainbow tables to try and brute force the cheese, however we were not very successful.

After numerous attempts, we got the hash `5ccdf4042bc999c778123fcbf6a295074bb8407fa2a86b635a90ffb8c22ddc53` 
that when decoded in https://hashes.com/en/decrypt/hash, returned:
![[Pasted image 20250324210520.png]]

`banon` was a cheese one of the cheeses given in the cheese_list.txt file from the room, and the `f` at the end was the salt. 

From this we realized that the hash consisted of individual lowercase lettered words from the cheese list that were converted to bytes and of which had a random salt in bytes attached to the end of it. 

Using this python program, we created a table of all the cheeses with each possible one byte hexadecimal salt. 

```
import hashlib

  

inputFile = open("cheese_list.txt","r")

outputFile = open("SHA256", "w")

  

def generateSHA256(plaintext):

    '''Takes plaintext and returns the sha256 of it'''

    h = hashlib.new('sha256') # Sha256 object hasher

    h.update(plaintext)

    return h.hexdigest()

  

for cheese in inputFile:

    cheese = ("".join(cheese.strip())).lower().encode()

    for salt in range(256):

  

        # Salt at the end of plaintext

        salted_cheese = cheese + salt.to_bytes()

        hashed_salted_cheese = generateSHA256(salted_cheese)

        outputFile.write(f'{hashed_salted_cheese}\tPlaintext: {cheese}: {salt:02x}\n')
```
Giving us the file `SHA256`with all combinations:
![[Pasted image 20250324211237.png]]

Then, we connect to the remote server `nc verbal-sleep.picoctf.net 54455` 

![[Pasted image 20250324211353.png]]

Take the encrypted cheese and search for it in the SHA256 file we created earlier that had the table of all cheeses.

![[Pasted image 20250324211516.png]]

Put it into the server:

![[Pasted image 20250324211607.png]]

and we get the flag!

![[Pasted image 20250324211627.png]]