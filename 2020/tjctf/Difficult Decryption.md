# Difficult Decryption

> Alice:  
Modulus: 491988559103692092263984889813697016406  
Base: 5  
Base ^ A % Modulus:  
232042342203461569340683568996607232345  
Bob:   
Got it.  
Here's my Base ^ B % Modulus:
76405255723702450233149901853450417505  
Alice:   
Thanks.  
Here's the encoded message:   
12259991521844666821961395299843462461536060465691388049371797540470  
I encoded it using this Python command: "message ^ (pow(your_key, A, modulus))". Your_key is Base ^ B % Modulus.  
After you decode the message, it will be a decimal number. Convert it to hex. You know what to do after that.  

Since the modulus is composite, discrete log becomes less hard.

> Modulus: 491988559103692092263984889813697016406  
Base: 5  
Base ^ A % Modulus:  
232042342203461569340683568996607232345  

sage input: 
```
R = Integers(491988559103692092263984889813697016406)
ga = R(232042342203461569340683568996607232345)
ga.log(5)
```
`25222735067058727456`

Hence A is `25222735067058727456`. The message is trivially unencrypted as 
`12259991521844666821961395299843462461536060465691388049371797540470 ^ (pow(your_key, A, modulus))`. 
