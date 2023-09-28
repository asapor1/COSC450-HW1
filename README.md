# COSC450-HW1

Please upload the Java source code (.java) files needed to Blackboard by the due date. 

Only two files are needed: groupnamea1client.java and groupnamea1server.java. 
Put these two files in a folder named groupnamea1, where groupname is the name assigned to your group 
on Blackboard.
There should not be any other classes used, needed, or downloaded (no nested classes etc.).
This means that only the uploaded source code in the two .java files are needed for your program to 
compile and run. 

Open two windows on your machine for running the client and server respectively. 
Include a readme file in each folder that tells a user how to run and test your program. 
The readme file should include a screenshot showing an actual example of input and output at the client 
and server when your program runs.

Go to
https://neilmadden.blog/2016/05/20/ephemeral-elliptic-curve-diffie-hellman-key-agreement-in-java/#more-2269
Get the ECDH java code from that site, modify it as needed.
Your code should not use javax.xml.bind.

Go to 
https://mkyong.com/java/java-aes-encryption-and-decryption/
Get the AES GCM Password-Based encryption and decryption java code from that site, modify 
it as needed.
Write a Java TCP socket program that does the following:
1. The server listens for client connections on port 24501
2. The ECDH code above is used to generate the shared derived key K as follows:
2.1 The client and server generate their key pairs (SPub, SPri) and (CPub, CPri)
2.2 The client and server exchange CPub and SPub
2.3 The client and server use ECDH to generate the shared derived key K
2.4 The client and server print: “generated derived key”
3. The AES GCM code above is used to encrypt and decrypt a message as follows:
3.1 The client and server convert the derived key K into the password string P
3.2 The client and server print “password:”and P
3.3 The client and server use P as the password for AES GCM encryption and decryption
3.4 The client generates a one-line text message M and prints “message M:” and M
3.5 The client uses AES GCM to encrypt M
3.6 The client sends the encrypted M to the server
3.7 The server decrypts it and prints “message M:” and M
