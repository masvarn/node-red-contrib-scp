const net = require("net");
const crypto=require("crypto");

module.exports = function (RED) {
    'use strict';

    function SCPNode(n) {
		RED.nodes.createNode(this, n);
		
var node = this;
node.on('input', function (msg, send, done) {

let client
let result
let payload
let remoteFile = msg.remote
let count = 3
let global_decrypt = false
let global_client_iv
let global_client_key
let global_client_mac
let global_server_iv
let global_server_key
let global_server_mac
let global_decipher
let global_cipher
let requested_message
let temp = Buffer.from([])
let global_pre_iv
let file = Buffer.from([])
let filelength = 0


let MESSAGE = {
    disconnect: buf("01"),
    kex_init:   buf("14"),
    kex_key:    buf("1e"),
    new_keys:   buf("15"),
    start_service: buf("05"),
    auth_request: buf("32"),
    open_channel: buf("5a"),
    channel_request: buf("62"),
    channel_data:   buf("5e"),
    channel_close:  buf("61")
}

let config={
    kex:"diffie-hellman-group1-sha1",
    server_host_key:"ssh-dss",
    c2s_cipher:"aes256-cbc",
    s2c_cipher:"aes256-cbc",
    c2s_mac:"hmac-sha1",
    s2c_mac:"hmac-sha1",
    c2s_compress:"none",
    s2c_compress:"none",
    language:"" //2x
}


class SSH{

	//TCP connection
	constructor(port,host){
		client = new net.Socket()
		client.on('data', data  =>{
            this.answer(data)
        	})
       		client.on('message', data  =>{
     		})
		client.on('error', err  => {
			this.error(err);
		})
		client.on('end', () => {
			this.error('ended')
		})
		client.connect(port, host)
	}
    async ssh(user,password){

    node.status({ fill: 'grey', shape: 'dot', text: 'downloading' });
    //intialise ssh
    let ident = "5353482d322e302d737368326a73302e342e31300d0a"   //ident string
    let buffer = buf(ident, 'hex')
    result = await this.request(buffer)
    
    let s_ident = result.slice(0,35)
    let s_kex_length = result.slice(37,37+4)
    s_kex_length = parseInt(s_kex_length.toString('hex'),16)-4
    let s_kex_payload = result.slice(37+5,37+s_kex_length)

    //kex 0x14
    let cookie = crypto.randomBytes(16);
    buffer = MESSAGE.kex_init    //message
    payload = parseconfig(config) 
    buffer = Buffer.concat([buffer,cookie,payload])
    let kex_payload = buffer
    buffer = padding(buffer);
    result = this.request(buffer)

    //kex with keys
    buffer = MESSAGE.kex_key //message
  
    const client_dh = crypto.getDiffieHellman('modp2');
    const client_kex = client_dh.generateKeys()

    let h_client_secret;

    //check higest order bit
    if (highest_order(client_kex) === false){
    buffer = Buffer.concat([buffer,buf("00000080",'hex'),client_kex])
    h_client_secret = Buffer.concat([buf("00000080",'hex'),client_kex]);
    }else{
    buffer = Buffer.concat([buffer,buf("0000008100",'hex'),client_kex])
    h_client_secret = Buffer.concat([buf("0000008100",'hex'),client_kex]);
    }

    buffer = padding(buffer)

    //send key
    result = await this.request(buffer)

    let number = result.slice(444,448).toString('hex');
    let server_host_key_payload = result.slice(6,10 + parseInt(result.slice(6,10).toString('hex'),16))

    //read f
    let server_secret;
    let h_server_secret;
    if (number === '00000080'){
        server_secret = result.slice(448,448+128)
        h_server_secret = Buffer.concat([buf("00000080",'hex'),server_secret]);
    }else{
        server_secret = result.slice(449,449+128)
        h_server_secret = Buffer.concat([buf("0000008100",'hex'),server_secret]);
    }

    let shared_secret = client_dh.computeSecret(server_secret)  //compute shared secret

//compute hash H

    let V_C = ident         //client id-string
    V_C = buf(V_C,'hex');
    V_C = V_C.slice(0,-2)
    V_C = length_buf(V_C)
    
    let V_S = s_ident       //server id-string
    V_S = length_buf(V_S)

    let I_C = length_buf(kex_payload)   //client kex payload

    let I_S = length_buf(s_kex_payload)

    let K_S = server_host_key_payload; //server host key

    let e = h_client_secret;   //DH client

    let f = h_server_secret;  //DH server
    
    let K       //shared secret

    //make sure highest order bit is 0
    if (highest_order(shared_secret) === false){
        K = Buffer.concat([buf("00000080",'hex'),shared_secret])
    }else{
        K = Buffer.concat([buf("0000008100",'hex'),shared_secret])
    }
    
    let hash= crypto.createHash('sha1')     //hash H
    .update(V_C)
    .update(V_S)
    .update(I_C)
    .update(I_S)
    .update(K_S)
    .update(e)
    .update(f)
    .update(K)
    let hash_H = hash.digest()

    // compute IVS and keys
    //client iv
    hash = crypto.createHash('sha1')
    .update(K)
    .update(hash_H)
    .update(buf('A','ascii'))
    .update(hash_H)
    let client_IV = hash.digest()
    client_IV = client_IV.slice(0,16)

    //server iv
    hash= crypto.createHash('sha1')
    .update(K)
    .update(hash_H)
    .update(buf('B','ascii'))
    .update(hash_H)
    let server_IV = hash.digest()
    server_IV = server_IV.slice(0,16)

    //client key
    hash= crypto.createHash('sha1')
    .update(K)
    .update(hash_H)
    .update(buf('C','ascii'))
    .update(hash_H)
    let client_key = hash.digest()
    hash = crypto.createHash('sha1')
    .update(K)
    .update(hash_H)
    .update(client_key)
    client_key = Buffer.concat([client_key,hash.digest()])
    client_key = client_key.slice(0,32)

    //server key
    hash= crypto.createHash('sha1')
    .update(K)
    .update(hash_H)
    .update(buf('D','ascii'))
    .update(hash_H)
    let server_key = hash.digest()
    hash = crypto.createHash('sha1')
    .update(K)
    .update(hash_H)
    .update(server_key)
    server_key = Buffer.concat([server_key,hash.digest()])
    server_key = server_key.slice(0,32)

    //client hmac key
    hash= crypto.createHash('sha1')
    .update(K)
    .update(hash_H)
    .update(buf('E','ascii'))
    .update(hash_H)
    let client_mac_key = hash.digest()

    //server hmac key
    hash= crypto.createHash('sha1')
    .update(K)
    .update(hash_H)
    .update(buf('F','ascii'))
    .update(hash_H)
    let server_mac_key = hash.digest()

    //write into global variables
    global_client_iv = client_IV
    global_server_iv = server_IV
    global_client_key = client_key
    global_server_key = server_key
    global_client_mac = client_mac_key
    global_server_mac = server_mac_key

    global_decipher = crypto.createDecipheriv('aes-256-cbc',server_key,server_IV)
    global_decipher.setAutoPadding(false)

    global_cipher = crypto.createCipheriv('aes-256-cbc',client_key,client_IV)
    global_cipher.setAutoPadding(false)

    // all keys are computed

    //kex done 0x15

    //  Message_New_Keys

    buffer = MESSAGE.new_keys //message
    buffer = padding(buffer)
    result = this.request(buffer)

    //all messages encrypted
    global_decrypt = true

    //start service "ssh-userauth" 0x05

    //  Message_service_request
    //  service name

    let service = "ssh-userauth"
    buffer = Buffer.concat([MESSAGE.start_service,length_buf(buf(service,'ascii'))]);
    buffer = padding(buffer)
    buffer = encrypt(buffer)

    requested_message = "06"
    result = await this.request(buffer)

    //user-Authentication 0x32

    //  Message_USER_AUTH_REQUEST
    //  username
    //  service to start after authentication
    //  "password"  (method of authentication)
    //  FALSE 0x00
    //  password    (actual password)
 
    service = length_buf(buf("ssh-connection",'ascii'))
    buffer = length_buf(buf("password",'ascii'))

    buffer = Buffer.concat([MESSAGE.auth_request,user,service,buffer,buf("00",'hex'),password])     
    buffer = padding(buffer)
    buffer = encrypt(buffer)

    requested_message = "34"
    result = await this.request(buffer)

    //channel open

    //  Message_Channel_open
    //  "session"
    //  recipient channel
    //  max window
    //  max packet

    let session = length_buf(buf("session",'ascii'));
    let channel0 = buf("00000000")   
    let window = buf("ffff000f")    //maxdata send throug channel
    let packet = buf("ff0003e8")    //max packet size

    buffer = Buffer.concat([MESSAGE.open_channel,session,channel0,window,packet])
    buffer = padding(buffer)
    buffer = encrypt(buffer)

    requested_message = "5b"
    result = await this.request(buffer)

    //open another channel

    let channel1 = buf("00000001")

    buffer = Buffer.concat([MESSAGE.open_channel,session,channel1,window,packet])
    buffer = padding(buffer)
    buffer = encrypt(buffer)

    requested_message = "5b"
    result = await this.request(buffer)

    //channel request 'exec'

    //  Message_Channel_Request
    //  recipient channel
    //  "exec"
    //  boolean true    
    //  command
    
    let execute = length_buf(buf("exec",'ascii'))
    let command = length_buf(buf(`ls -la ${remoteFile} | tr -s ' '| cut -d' ' -f5`,'ascii'))
    buffer = Buffer.concat([MESSAGE.channel_request,channel0,execute,buf("01"),command])
    buffer = padding(buffer)
    buffer = encrypt(buffer)

    requested_message = "5e"
    result = await this.request(buffer)
    result = parseInt(result.toString('ascii'),10)
    let file_length = result

    //channel request file

    command = length_buf(buf(`scp -f ${remoteFile}`,'ascii'))
    buffer = Buffer.concat([MESSAGE.channel_request,channel1,execute,buf("01"),command])
    buffer = padding(buffer)
    buffer = encrypt(buffer)

    requested_message = "5d"
    result = await this.request(buffer)


    //channel send data

    //  Message_Data
    //  recipient channel
    //  data
    
    payload = length_buf(buf([0]))
    buffer = Buffer.concat([MESSAGE.channel_data,channel1,payload])
    buffer = padding(buffer)
    buffer = encrypt(buffer)
    requested_message = "5e"
    result = await this.request(buffer)
    filelength = file_length
    
    //again to start data transfer

    payload = length_buf(buf([0]))
    buffer = Buffer.concat([MESSAGE.channel_data,channel1,payload])
    buffer = padding(buffer)
    buffer = encrypt(buffer)
    requested_message = "5e"
    result = await this.request(buffer)
    let databuffer = result
    //and again to confirm download is completed

    payload = length_buf(buf([0]))
    buffer = Buffer.concat([MESSAGE.channel_data,channel1,payload])
    buffer = padding(buffer)
    buffer = encrypt(buffer)

    requested_message = "62"
    result = await this.request(buffer)
    
    //close channel 0

    //  Message_Channel_close
    //  recipient

    buffer = Buffer.concat([MESSAGE.channel_close,channel0])
    buffer = padding(buffer)
    buffer = encrypt(buffer)

    result = this.request(buffer)

    //close channel 1

    buffer = Buffer.concat([MESSAGE.channel_close,channel1])
    buffer = padding(buffer)
    buffer = encrypt(buffer)

    result = this.request(buffer)
    

    //disconnect

    //  Message_Disconnect
    //  reason code 
    //  reason as string
    //  language tag

    let reason = length_buf(buf(""))    //empty
    let language = length_buf(buf(""))      //empty
    buffer = Buffer.concat([MESSAGE.disconnect,reason,language])
    buffer = padding(buffer)
    buffer = encrypt(buffer)
 
    requested_message = "01"
    result = this.request(buffer)
    node.status({ fill: 'blue', shape: 'dot', text: 'done' });
    this.logoff()
    return databuffer
    }

//send to server and wait for incoming data
request(message){
    const promise = new Promise((resolve, reject) => this.responsePromise = {resolve, reject});
    client.write(message);
    return promise;
}

// parses incoming data
// server may send one message or more in one response, long messages may be split into multiple responses
// this function makes sure every message is decrypted and no data gets lost
// because the cipher uses cipher-block-chaining special care was put in order to avoid decrypting wrong parts of messages which would result in a currupt IV
answer(data){
   if (global_decrypt === false){
	   // data needs no decryption
    this.responsePromise.resolve(data);
   }else{
	   // data need decryption
    temp = Buffer.concat([temp,data]) //buffering incoming data
    data = temp
   
       let plain = decrypt(data,0,16)			// decrypt first 16 byte to gain length of message
       let length = parseInt(plain.slice(0,4).toString('hex'),16)	// length of message to decrypt

       let expectedbytes = length + 4			//expected bytes of incoming message
    
       if (expectedbytes <= (data.length - 20)){	// if the announced message is longer than the data stored in temp, no further processing takes place
	       						// promise won't be fulfilled so programm is in a waiting state.
        if (expectedbytes <= 16){ 
            this.responsePromise.resolve(plain)
            temp = Buffer.from([])
        }else{
        plain = Buffer.concat([plain,decrypt(data,16,length+4)])	// decrypt all, FYI: HMAC is not decrypted thats why often 24 are subtracted
        temp = temp.slice(length+24)			//remove decrypted message+HMAC from temp

       while(length + 16 < (data.length - 24)){		//data may contain multiple messages, loop makes sure every COMPLETE message is processed/decrypted
        data = data.slice(length+24);
        let decrypted = decrypt(data,0,16)
        length = parseInt(decrypted.slice(0,4).toString('hex'),16)

        if (length > (data.length - 24)){ 
							// same as before, remaining data doesn't contain full message so iv is resetted, explenation see below
            global_server_iv = global_pre_iv
        }else{
        plain = Buffer.concat([plain,decrypted])
        if (length >16){
        plain = Buffer.concat([plain,decrypt(data,16,length+4)])
        }
        temp = temp.slice(length+24)
    }
        }
         this.parse4promise(plain)	//return promise

        }}else {
		// initialisation vector is resetted so that next time the temp is filled, decryption works again for the first 16 byte of the message
            global_server_iv = global_pre_iv
    }

}}

parse4promise(input){

    while(input.length>0){
        let length = parseInt(input.slice(0,4).toString('hex'),16)
        let data = input.slice(0,length+4)
        input = input.slice(length+4)

        if (data.slice(5,6).toString('hex') === "5f"){
            this.error("Server: "+parsedata(data).toString('ascii'))
        }else if (data.slice(5,6).toString('hex') === "01"){
            this.error("Server: Disconnected: "+parsedata(data).toString('ascii'))
        }else if (data.slice(5,6).toString('hex') === "5e"){
            data = parsedata(data)
            file = Buffer.concat([file,data])
            if (filelength <= file.length){
                this.responsePromise.resolve(file)
                file = Buffer.from([])
            }
        }
        else if (data.slice(5,6).toString('hex') === requested_message){
            this.responsePromise.resolve(data)
        }
    }
}

logoff(){
	client.destroy();
}
error(err){
	this.responsePromise.reject(err);
	this.logoff();
}
}

//encryption+hmac
function encrypt(plain){
    
    let mac = crypto.createHmac('sha1',global_client_mac)
   
    let hmac = mac.update(Buffer.concat([buf(count.toString(16).padStart(8,'0')),plain])).digest()
    count++

    let encrypted;
    if (plain.length < 2 ){
        encrypted = global_cipher.update(plain,"binary","binary")
        encrypted = buf(encrypted,"binary")
    }else{
        encrypted = buf(global_cipher.update(plain.slice(0,16),"binary","binary"),"binary")
        encrypted = Buffer.concat([encrypted,buf(global_cipher.update(plain.slice(16),"binary","binary"),'binary')])
    }
    return Buffer.concat([encrypted,hmac])
  }

//decryption
function decrypt(encrypted,first,second){
    let plain
   // console.log(encrypted)
    encrypted = encrypted.slice(first,second)
   // console.log(encrypted)
    global_decipher = crypto.createDecipheriv('aes-256-cbc',global_server_key,global_server_iv)
    global_decipher.setAutoPadding(false)
    
    plain = global_decipher.update(encrypted,"binary","binary")
    plain = buf(plain,"binary")

    global_pre_iv = global_server_iv
    
    global_server_iv = encrypted.slice(-16)
    
    
    //global_server_iv = global_pre_iv for reset
    return plain
  }

  //adds length and padding
  function padding(data){
    data = Buffer.concat([Buffer.allocUnsafe(5),data,Buffer.allocUnsafe(4)]) //minimum length
    let newdata = Buffer.allocUnsafe(data.length+(16-((data.length)%16)))    //new Buffer with correct length
    let randombytes = crypto.randomBytes(16-((data.length)%16)+4)            //random padding with correct length
    data = data.slice(0,-4)                                                  //
    data.copy(newdata)                                                       //min length into correct length
    let paddinglength=buf(randombytes.length.toString(16).padStart(2,'0'))   //length of padding
    randombytes.copy(newdata,data.length)                                    //
    let length = buf((newdata.length - 4).toString(16).padStart(8,'0'))      //length of message
    length.copy(newdata)                                                     //into message
    paddinglength.copy(newdata,4)                                            //into message
    return newdata;
  }
//creates the kex_init payload
function parseconfig(config){
    let kex = Buffer.concat([buf(config.kex.length.toString(16).padStart(8,'0'),'hex'),buf(config.kex,'ascii')])
    let hk = Buffer.concat([buf(config.server_host_key.length.toString(16).padStart(8,'0'),'hex'),buf(config.server_host_key,'ascii')])
    let cipher1 = Buffer.concat([buf(config.c2s_cipher.length.toString(16).padStart(8,'0'),'hex'),buf(config.c2s_cipher,'ascii')])
    let cipher2 = Buffer.concat([buf(config.s2c_cipher.length.toString(16).padStart(8,'0'),'hex'),buf(config.s2c_cipher,'ascii')])
    let mac1 = Buffer.concat([buf(config.c2s_mac.length.toString(16).padStart(8,'0'),'hex'),buf(config.c2s_mac,'ascii')])
    let mac2 = Buffer.concat([buf(config.s2c_mac.length.toString(16).padStart(8,'0'),'hex'),buf(config.s2c_mac,'ascii')])
    let com1 = Buffer.concat([buf(config.c2s_compress.length.toString(16).padStart(8,'0'),'hex'),buf(config.c2s_compress,'ascii')])
    let com2 = Buffer.concat([buf(config.s2c_compress.length.toString(16).padStart(8,'0'),'hex'),buf(config.s2c_compress,'ascii')])
    let lang1 = Buffer.concat([buf(config.language.length.toString(16).padStart(8,'0'),'hex'),buf(config.language,'ascii')])
    let lang2 = Buffer.concat([buf(config.language.length.toString(16).padStart(8,'0'),'hex'),buf(config.language,'ascii')])
    let pads= buf("0000000000",'hex')

    return Buffer.concat([kex,hk,cipher1,cipher2,mac1,mac2,com1,com2,lang1,lang2,pads]);
}

//checks the highest order bit
function highest_order(data){
    let number = data.toString('hex').slice(0,2)
    number= (parseInt(number, 16).toString(2)).padStart(8, '0')
    if (number.slice(0,1)=== '0'){
    return false
    }else{
    return true
    }
}

//concatenates length of a buffer with the buffer
function length_buf(buffer){
    return Buffer.concat([buf(buffer.length.toString(16).padStart(8,'0'),'hex'),buffer]);
}
//shortcut for creating Buffer
function buf(buffer,encoding){
    if (!encoding){
        encoding = "hex"
      }
    return Buffer.from(buffer,encoding)
}

//parsing output data
function parsedata(data){
    let padding = parseInt(data.slice(4,5).toString('hex'),16)
    return data.slice(14,-(padding))
}




//start

node.status({ fill: 'grey', shape: 'dot', text: 'starting' });
async function download(user,password){
    try{
        node.status({ fill: 'blue', shape: 'dot', text: 'starting' });
        const ssh = new SSH(22,msg.host)
        let result = await ssh.ssh(user,password);
        msg.payload = result
        node.send(msg)
    }catch(err){
        console.log("Error: ",err)
        node.status({ fill: 'red', shape: 'dot', text: 'error' });
        done(err)
    }
}

let user = length_buf(buf(msg.user,'ascii'))
let password = length_buf(buf(msg.password,'ascii'))
node.status({ fill: 'red', shape: 'dot', text: 'starting' });
msg.path = msg.remote;
var lengthpath = msg.path.slice(-1);
if (lengthpath === '/'){
	msg.payload = '';
	node.send(msg);
}else{
    
    download(user,password);
}


});
}
RED.nodes.registerType('scp-download', SCPNode);
}
