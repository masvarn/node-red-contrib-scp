# Description

The intended use for this node is to download files from a Siemens NCU.
Currently only aes-256-cbc, dh-g1-sha1, hmac-sha1!


## Installation

    npm install node-red-contrib-scp -g

## Usage

Example of a Node-Red function to feed the node

```js
msg.remote = "remote/path/to/file.txt";
msg.host = "192.168.XX.XXX";
msg.user = "user";
msg.password = "password";
```

The output will be a `msg.payload` containing a Buffer of your file.
If no file is found the node will output an empty string and throw an error.

## TODO

- better html
- way to edit algorithms in node-red