Padding oracle exploit challenge manual
===========================

The goal of this challenge is to find a flag contained in an encrypted message. A decryption oracle and the encrypted message is provided. The student should write an application that cracks the cyphertext by abusing the oracle which is vulnerable to the padding attack.

Prerequisites
-----------------
You will need the following items to run the challenge:

 - Python 3 interpreter (>=3.3)
 - Flask library for Python 3
 - PyCrypto library for Python 3
 - a way to generate secrets

Creating the message
-----------------------------
The first step of course is to **generate a flag** that solves the challenge. This can be an arbitrary long string. As we are using 256 bit AES with CBC for encryption, we need to **generate a 256 bit key and and a 16 byte initialization vector** for the algorithm. This should be done with safe random number generators. (Not provided.) By having these three components, we are ready to encrypt the message. 
The `padex.py` executable Python 3 script has this functionality through the `create` command. The program  `padex.py create <key32> <iv16> <flag>`  is input three arguments :

 - `key32`: the 32 byte key encoded in base64
 - `iv16`: the 16 byte initialization vector encoded in base64
 - `flag`: the flag string that solves the challenge
 
It will assemble the message with the following content:

    Congrats, your flag is '<flag>'

(where `<flag>` is the flag).  The created message is then padded to extend its length to a multiple of 16 bytes. This is done using the followig method:

 - each padding byte contains the padding length 
 - padding is always added, even if the message is a multiple of 16 (resulting in an extra block full of `0x10`s)
 
Finally, the message gets encrypted with the key and IV.


> **Warning**
> The IV is kept secret, meaning that the first block of the message can't be cracked with this attack. However it only contains the `Congrats, your f` characters, so the challenge remains solvable anyways.

Running the oracle
-------------------------
The oracle is web application contained in the same executable script as the message encryptor. It has two required and two optional arguments.

 - `key32`: the same key with which the message was encrypted 
 - `iv16`: the same IV with which the message was encrypted
 - `--host`: optional host argument,  `localhost` by default
 -  `--port`: optional host argument,  `12345` by default

Run `padex.py run <key32> <iv16>`  to start the Flask app at the given host an port. Messages should be sent to the root of the host, e.g. http://127.0.0.1:12345/. The following restrictions apply to the requests:

 - the HTTP method should be POST,
 - the message is sent in HTTP message body and should be encoded in base64,
 - the message length should be exactly 44 characters. (We need 32 byte long fragments for the attack, which is 44 bytes encoded with base64)
 
The response will be a **200 - OK** when the padding is good, and **403 - Forbidden** if the padding is bad. Other response codes indicate that something is wrong with the request, the network or the world.

If the student sends a GET message to the oracle, *templates/index.html* is rendered. It can be useful as a help page.

Attack example
---------------------
I implemented an attack script as an executable Python 3 application to prove that the challenge is solvable. You can run it with  `attack.py run <message> <url>` where:

 - `message` is the encrypted message
 - `url` is the URL of the oracle, e.g. http://127.0.0.1:12345

The script successfully cracks the message in the following setup:

**flag**: Tqpu2efLxJLUn3XJQ4rbzW9G5gU27v9e
**key (b64)**:  VHFwdTJlZkx4SkxVbjNYSlE0cmJ6VzlHNWdVMjd2OWU=
**IV (b64)**: WkJNQVZGbkU3OXVCQU5TVg==

----------
**message (b64)**:
/LA0Us7iIXaxTid25gdlIePo8MHYgeBexPGCByF5R8SnrJ4KdTXl/I5SdHQnIS/K2MpuZ+oYBxvnLY5UuAqDDA==


----------
Run  `padex.py run VHFwdTJlZkx4SkxVbjNYSlE0cmJ6VzlHNWdVMjd2OWU= WkJNQVZGbkU3OXVCQU5TVg==` to start the server

Run the attack from another terminal: `attack.py "/LA0Us7iIXaxTid25gdlIePo8MHYgeBexPGCByF5R8SnrJ4KdTXl/I5SdHQnIS/K2MpuZ+oYBxvnLY5UuAqDDA==" "http://127.0.0.1:12345"`

You should get the message  after a few seconds in a Python `bytearray`:

    b"\x19-#&$'\x1a6\x1b\x19\x0c-4<s0lag is 'Tqpu2efLxJLUn3XJQ4rbzW9G5gU27v9e'\x07\x07\x07\x07\x07\x07\x07"
   
The first 16 bytes are obscured because the IV is unknown, but it doesn't matter, as the flag is in the single quotes.


----------

> *Challenge created by **Szakállas Dávid*** 
> david.szakallas(at)gmail.com
> 
> This work is based on the slides of Prof. Levente Buttyán, and was created as an assignment for the course <a href="http://www.hit.bme.hu/~buttyan/courses/BMEVIHIMA05/index.html">
        Cryptographic Protocols</a> at Budapest University of Technology and Economics.

