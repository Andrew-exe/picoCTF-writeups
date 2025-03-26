 
#**Homeless Sasquatch - Advay Gude**

#**This Method Only Work for Encrypted Cheeses That Have No Spaces**

 
When loading the room description up with are shown:
![alt text](https://github.com/Andrew-exe/picoCTF-writeups/blob/main/Pasted%20image%2020250324172052.png)
with this hint:
![alt text](https://github.com/Andrew-exe/picoCTF-writeups/blob/main/Pasted%20image%2020250324172104.png)
Using the hint we realized the secret cheese was likely encrypted with an Affine Cipher as it used linear equations.

When running the instance it returned:
![alt text](https://github.com/Andrew-exe/picoCTF-writeups/blob/main/Pasted%20image%2020250325123738.png)
It asks use whether we would like to guess the cheese or encrypt something. It also gives us the encrypted hash 
 
We noticed that guess my cheese part 2 had a list of specific cheeses. We decided to encrypt a cheese
![[Pasted image 20250325124046.png]]

We went to the website, [https://www.dcode.fr/affine-cipher](https://www.dcode.fr/affine-cipher "https://www.dcode.fr/affine-cipher"), and put in the cheese we encrypted to brute force (automatic brute force decryption) the A and B coefficients of the Affine Cipher
![alt text](https://github.com/Andrew-exe/picoCTF-writeups/blob/main/Pasted%20image%2020250324213222.png)

With the coefficients of A is 7 and B is 5 we got the decrypted cheese, **Acorn**.
Then we replace those values to where it says to put the A and B coefficients

![alt text](https://github.com/Andrew-exe/picoCTF-writeups/blob/main/Pasted%20image%2020250325123255.png)


After we replace those numbers, we go back to the remote connections and we get the original encoded cheese and the paste it back into the affine decoder.

![alt text](https://github.com/Andrew-exe/picoCTF-writeups/blob/main/Pasted%20image%2020250325123328.png)

Then instead of using the automatic brute force decryption we use the manual option with the inputted A and B coefficients and used the decrypt option. 
It outputted the:

![alt text](https://github.com/Andrew-exe/picoCTF-writeups/blob/main/Pasted%20image%2020250325123353.png)


Using this we go back to the instance and choose the guess option and paste the results we got from the affine cipher.
![alt text](https://github.com/Andrew-exe/picoCTF-writeups/blob/main/Pasted%20image%2020250325123457.png)


After inputting this we should get the flag: 

![alt text](https://github.com/Andrew-exe/picoCTF-writeups/blob/main/Pasted%20image%2020250325123525.png)
The flag is: **picoCTF{ChEeSy696d4adc}** 
