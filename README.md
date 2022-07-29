# Md5 length extension attack example

This is a simple example of how a length extension attack works with md5.

Because an md5 hash is just a representation of the internal state after processing a message, we can create the hash for message<sub>1</sub> &#124;&#124; message<sub>2</sub> without needing to know the content of message<sub>1</sub>.  All we need is the hash and the length of message<sub>1</sub> to initialise the md5 algorithm to the state it was in after processing message<sub>1</sub> and then process message<sub>2</sub> to get the new hash.

This is an issue when md5 is used as a MAC using hash(secret &#124;&#124; message) because we can generate a new, valid MAC for and extended message without ever knowing the secret.  For example, if we were to create a MAC using the secret 'mysecretkey':

```
$ md5 -s 'mysecretkeyThis is my message'
MD5 ("mysecretkeyThis is my message") = 686acc1d3956791ef5526207521cd98f
```

we could use the length extension weakness of md5 to generate a new (extended) message and a new (valid) MAC according to this scheme:

```
$ python lenext.py --mac 686acc1d3956791ef5526207521cd98f \
                   --msg 'This is my message' \
                   --keylen 11 \
                   --ext 'this has been tampered with' \
                   --out tampered.msg
ee38721f19f1f4fb27eebdfd9d5d5ff0
```

This new MAC is the MAC for the tampered message that we were able to create without knowledge of the secret key.  We can check it's valid according to this MAC scheme:

```
$ echo -n 'mysecretkey' | cat - tampered.msg | md5
ee38721f19f1f4fb27eebdfd9d5d5ff0
```
