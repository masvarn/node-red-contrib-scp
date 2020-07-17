const Client = require('ssh2');

module.exports = function (RED) {
    'use strict';

    function SCPNode(n) {
		RED.nodes.createNode(this, n);
		
		var node = this;
        node.on('input', function (msg, send, done) {
			
			function handleError(error, msg) {
                if (done) {
                    // Node-RED 1.0 compatible
                    done(error);
                } else {
                    // Node-RED 0.x compatible
                    node.error(error, msg);
                }
			}
//settings
		
let conSettings={
	host: msg.host,
	port: '22',
	username: msg.username,
	password: msg.password
};
//algorithms for encryption 
const halg='hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-md5,hmac-sha2-256-96,hmac-sha2-512-96,hmac-ripemd160,hmac-sha1-96,hmac-md5-96';
const calg='none,zlib@openssh.com,zlib';
const kalg='diffie-hellman-group1-sha1,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1';
const hoalg='ssh-dss,ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521';
const cialg='aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm,aes128-gcm@openssh.com,aes256-gcm,aes256-gcm@openssh.com,aes256-cbc,aes192-cbc,aes128-cbc,blowfish-cbc,3des-cbc,arcfour256,arcfour128,cast128-cbc,arcfour';
conSettings.algorithms = {
	kex: kalg.split(','),
	cipher: cialg.split(','),
	serverHostKey: hoalg.split(','),
	hmac: halg.split(','),
	compress: calg.split(',')
};

let filesize=0;
let datasize=0;	
//Check if path is directory
var lengthpath=msg.remote.slice(-1);
if (lengthpath==='/'){
	msg.payload='';
	node.send(msg);
}else{
	node.status({ fill: 'yellow', shape: 'dot', text: 'connecting' });
	start(); //start download function
}
			 
//connection
async function start(){
	try{
		await download();
	}catch(err){
		done(err)
	}
}

async function download(){
 try {
		return new Promise((resolve, reject) => {
			const conn = new Client();		//new ssh2 client
			let remoteFile = msg.remote;	
			let localFile = msg.local;
			conn.connect(conSettings);		//connect with given settings
			conn.on('ready', () => {		//connected
				node.status({ fill: 'green', shape: 'dot', text: 'connected' });
				const Scp = new ScpConn(conn);		//start SCP
				Scp.getFile(remoteFile, localFile, (err, data) => {
					if (err) {
						node.status({ fill: 'red', shape: 'dot', text: 'download failed' });
						reject(err);
					}
					else {
						node.status({ fill: 'grey', shape: 'dot', text: 'download completed' });
						msg.payload = data;				//buffer of data
						datasize = data.length;

						conn.end();
					}
				});

				//get filesize to make sure download was successful
				Scp.getFileSize(remoteFile, (err_1, size) => {
					if (err_1)
						callback(err_1);
					else {
						filesize = parseInt(size, 10);
					}
				});
				resolve('done');
			});
			conn.on('error', err_2 => {
				node.status({ fill: 'red', shape: 'dot', text: 'failed' });
				reject(err_2);
			});

			conn.on('end', () => {
				if (filesize === datasize) {
					msg.fail = 0;
					node.send(msg)
					resolve('end');
							//compare filesizes
				}
				else{
				msg.fail = 1;
				er="download incomplete"+"Download: "+datasize+" On Server: "+filesize
				done(er)
				reject(er)
				}
				
			});
			conn.on('close', () => {
				resolve('done');
			});

		});
	}
	catch (err_3) {
		done(err_3);
	}
}
//Secure Copy Protocol
class ScpConn{
	constructor(connection){
		this.conn=connection
	}
	//download File
	getFile(remoteFile, localFile, callback) {
		let self = this;
		//let filesize;
		this.getFileSize(remoteFile,(err,size)=>{
		   if (err) callback(err);
  
		   filesize=size;
		})
		self.conn.exec(`scp -f ${remoteFile}`, (err, stream) => { //execute copy command
		   if (err) callback(err,null);
  
		   let file = Buffer.from([0]);
		   stream.write(Buffer.from([0]));
		   stream.on('close', () => {
		
			callback(null,file.slice(1, -1));
			stream.end();
			  
		   });
  
		   let erase = 0;
		   stream.on('data', (data) => {
			  if (erase === 0) {
				 erase = 1;
				 stream.write(Buffer.from([0]));
				 return;
			  }
			  file = Buffer.concat([file, data]);
			  if (file.length >= filesize){
				 stream.write(Buffer.from([0]));
			  }
  
			  
		   });
  
		   stream.stderr.on('data', data => {
			  done(`Err: "${data}"`);
		   });
		});
	 }
	
//remote file size
	 getFileSize(remoteFile, callback) {
		let self = this;
		self.conn.exec(`ls -la ${remoteFile} | tr -s ' '| cut -d' ' -f5`, (err, stream) => {
		   if (err) callback(err);
		   stream.on('data', data => {
			callback(null, data.toString());
		   });
  
		   stream.stderr.on('data', data => {
			  done(`STDERR: "${data}"`);
		   });
		});
	 }

}
});
}
RED.nodes.registerType('scp-download', SCPNode);
}