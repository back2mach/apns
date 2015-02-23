use byteorder::{BigEndian, ReaderBytesExt, WriterBytesExt};

use rustc_serialize::Encodable;
use rustc_serialize::Encoder;
use rustc_serialize::json;

use openssl;
use openssl::ssl;
use openssl::ssl::SslStream;
use openssl::ssl::error::SslError;

use std::cell::RefCell;
use std::num::Int;
use std::ops::{Range, Index};
use std::old_io::net;
use std::old_io::net::ip::SocketAddr;
use std::old_io::{TcpStream, MemReader};
use std::old_path::posix::Path;
use std::collections::HashMap;

use rand;
use time;

#[derive(Debug)]
pub struct Payload<'a> {
	pub aps: PayloadAPS<'a>,
	pub info: Option<HashMap<&'a str, &'a str>>
}

#[derive(Debug)]
pub struct PayloadAPS<'a> {
	pub alert: PayloadAPSAlert<'a>,
	pub badge: Option<i32>,
	pub sound: Option<&'a str>,
	pub content_available: Option<i32>
}

#[derive(Debug)]
pub enum PayloadAPSAlert<'a> {
	Plain(&'a str),
	Localized(&'a str, Vec<&'a str>)
}

impl<'a> Encodable for Payload<'a> {
	fn encode<S: Encoder>(&self, encoder: &mut S) -> Result<(), S::Error> {
	    match *self {
			Payload{ref aps, ref info} => {
				if let Some(ref map) = *info {
	    	        encoder.emit_struct("Payload", 1 + map.len(), |encoder| {
						try!(encoder.emit_struct_field( "aps", 0usize, |encoder| aps.encode(encoder)));
						let mut index = 1usize;
						for (key, val) in map.iter() {
							try!(encoder.emit_struct_field(key, index, |encoder| val.encode(encoder)));
							index = index + 1;
						}
						Ok(())
	    	        })
				}
				else {
	    	        encoder.emit_struct("Payload", 1, |encoder| {
						try!(encoder.emit_struct_field( "aps", 0usize, |encoder| aps.encode(encoder)));
						Ok(())
	    	        })
				}
			}
		}
	}
}

impl<'a> Encodable for PayloadAPS<'a> {
	fn encode<S: Encoder>(&self, encoder: &mut S) -> Result<(), S::Error> {
	    match *self {
			PayloadAPS{ref alert, ref badge, ref sound, ref content_available} => {
    	        encoder.emit_struct("PayloadAPS", 4, |encoder| {
					try!(encoder.emit_struct_field( "alert", 0usize, |encoder| alert.encode(encoder)));
					try!(encoder.emit_struct_field( "badge", 1usize, |encoder| badge.encode(encoder)));
					try!(encoder.emit_struct_field( "sound", 2usize, |encoder| sound.encode(encoder)));
					try!(encoder.emit_struct_field( "content-available", 3usize, |encoder| content_available.encode(encoder)));
					Ok(())
    	        })
			}
		}
	}
}

impl<'a> Encodable for PayloadAPSAlert<'a> {
	fn encode<S: Encoder>(&self, encoder: &mut S) -> Result<(), S::Error> {
	    match *self {
			PayloadAPSAlert::Plain(ref str) => {
    	        encoder.emit_str(str)
			},
			PayloadAPSAlert::Localized(ref key, ref args) => {
    	        encoder.emit_struct("PayloadAPSAlert", 2, |encoder| {
					try!(encoder.emit_struct_field( "loc-key", 0usize, |encoder| key.encode(encoder)));
					try!(encoder.emit_struct_field( "loc-args", 1usize, |encoder| args.encode(encoder)));
					Ok(())
				})
			}
		}
	}
}

#[allow(dead_code)]
fn hex_to_int(hex: &str) -> u32 {
	let mut total = 0u32;
	let mut n = hex.to_string().capacity() - 1;
		
	for c in hex.chars() {
		match c {
			'0'...'9' => {
				total += 16.pow(n) * ((c as u32) - ('0' as u32));
			},
			'a'...'f' => {
				total += 16.pow(n) * ((c as u32) - ('a' as u32) + 10);
			},
			_ => {
			}
		}
		n = n - 1;
	}
	
	return total;
}

#[allow(dead_code)]
fn convert_to_binary(device_token: &str) -> Vec<u8> {
	let mut device_token_bytes: Vec<u8> = vec![];
	for i in 0..8 {
		let string = device_token.to_string();
		let range = Range{start:i*8, end:i*8+8};
		let sub_str = string.index(&range);
		
		let sub_str_num = hex_to_int(sub_str);
		let mut sub_str_bytes = vec![];
		let _ = sub_str_bytes.write_u32::<BigEndian>(sub_str_num);
		
		device_token_bytes.push_all(sub_str_bytes.as_slice());
	}
	device_token_bytes.shrink_to_fit();
		
	return device_token_bytes;
}

#[allow(dead_code)]
pub fn convert_to_token(binary: &[u8]) -> String {
	let mut token = "".to_string();
	for i in 0..8 {
		let range = Range{start:i*4, end:i*4+4};
		let sub_slice = binary.index(&range);
		
		let mut rdr = MemReader::new(sub_slice.to_vec());
		let num = rdr.read_u32::<BigEndian>().unwrap();
		
		token = format!("{}{:x}", token, num);
	}
	return token;
}

#[allow(dead_code)]
pub fn convert_to_timestamp(binary: &[u8]) -> u32 {
	let mut rdr = MemReader::new(binary.to_vec());
	let num = rdr.read_u32::<BigEndian>().unwrap();
	
	return num;
}

pub struct APNS {
	pub sandbox: bool,
	pub certificate: Path,
	pub private_key: Path,
	pub ca_certificate: Path,
	pub ssl_stream: RefCell<SslStream<TcpStream>>
}

impl APNS {
	pub fn new(sandbox: bool, cert_file: Path, private_key_file: Path, ca_file: Path) -> APNS {
		let apns_url_production = "gateway.push.apple.com";
		let apns_url_development = "gateway.sandbox.push.apple.com";
		let apns_port = 2195;
		
		let apns_url = if sandbox {
			apns_url_development
		}
		else {
			apns_url_production
		};
		
		let ssl_stream = RefCell::new(get_ssl_stream(apns_url, apns_port, &cert_file, &private_key_file, &ca_file).unwrap());	
			
		APNS{sandbox: sandbox, certificate: cert_file, private_key: private_key_file, ca_certificate: ca_file, ssl_stream: ssl_stream}
	}
	
	#[allow(dead_code)]
    pub fn get_feedback(&self) -> Vec<(u32, String)> {    
		let apns_feedback_production = "feedback.push.apple.com";
		let apns_feedback_development = "feedback.sandbox.push.apple.com";
		let feedback_port = 2196;
        
		let apns_feedback_url = if self.sandbox {
			apns_feedback_development
		}
		else {
			apns_feedback_production
		};
		
		let mut stream = get_ssl_stream(apns_feedback_url, feedback_port, &self.certificate, &self.private_key, &self.ca_certificate).unwrap();
		
		let mut tokens: Vec<(u32, String)> = Vec::new();
        loop {
			let mut read_buffer = [0u8; 38];
			if let Err(..) = stream.read(&mut read_buffer) {
/*                println!("Feedback read error {:?}", error);*/
				break;
            }
			
			let time_range = Range{start:0, end:4};
			let time_slice = read_buffer.index(&time_range);
			let time = convert_to_timestamp(time_slice);
			
			let token_range = Range{start:6, end:38};
			let token_slice = read_buffer.index(&token_range);
            let token = convert_to_token(token_slice);
						
			tokens.push((time, token));
        }

        return tokens;
    }

	#[allow(dead_code)]
	pub fn send_payload(&self, payload: Payload, device_token: &str) {
		let payload_str = match json::encode(&payload) {
			Ok(json_str) => {
				json_str.to_string()
			}
			_ => { return; }
		};
	
		let payload_bytes = payload_str.into_bytes();
		let device_token_bytes: Vec<u8> = convert_to_binary(device_token);
	
		let mut notification_buffer: Vec<u8> = vec![];
		let mut message_buffer: Vec<u8> = vec![];
	
		// Device token
		let mut device_token_length = vec![];
		let _ = device_token_length.write_u16::<BigEndian>(device_token_bytes.capacity() as u16);
	
		message_buffer.push(1u8);
		message_buffer.push_all(device_token_length.as_slice());
		message_buffer.push_all(device_token_bytes.as_slice());
	
		// Payload
		let mut payload_length = vec![];
		let _ = payload_length.write_u16::<BigEndian>(payload_bytes.capacity() as u16);
	
		message_buffer.push(2u8);
		message_buffer.push_all(payload_length.as_slice());
		message_buffer.push_all(payload_bytes.as_slice());
		
		// Notification identifier
		let payload_id = rand::random::<u32>();
		let mut payload_id_be = vec![];
		let _ = payload_id_be.write_u32::<BigEndian>(payload_id);
	
		let mut payload_id_length = vec![];
		let _ = payload_id_length.write_u16::<BigEndian>(payload_id_be.capacity() as u16);
	
		message_buffer.push(3u8);
		message_buffer.push_all(payload_id_length.as_slice());
		message_buffer.push_all(payload_id_be.as_slice());
	
		//	Expiration date
		let time = time::now().to_timespec().sec + 86400;	// expired after one day
		let mut exp_date_be = vec![];
		let _ = exp_date_be.write_u32::<BigEndian>(time as u32);
	
		let mut exp_date_length = vec![];
		let _ = exp_date_length.write_u16::<BigEndian>(exp_date_be.capacity() as u16);
	
		message_buffer.push(4u8);
		message_buffer.push_all(exp_date_length.as_slice());
		message_buffer.push_all(exp_date_be.as_slice());
	
		// Priority
		let mut priority_length = vec![];
		let _ = priority_length.write_u16::<BigEndian>(1u16);
	
		message_buffer.push(5u8);
		message_buffer.push_all(priority_length.as_slice());
		message_buffer.push(10u8);
	
		message_buffer.shrink_to_fit();
	
		let mut message_buffer_length = vec![];
		let _ = message_buffer_length.write_u32::<BigEndian>(message_buffer.capacity() as u32);
		
		let command = 2u8;
		notification_buffer.push(command);
		notification_buffer.push_all(message_buffer_length.as_slice());
		notification_buffer.push_all(message_buffer.as_slice());
		
	    let mut retry_count = 3;	
		while let Err(error) = self.ssl_stream.borrow_mut().write_all(&notification_buffer) {
			println!("ssl_stream write error {:?}", error);

            retry_count = retry_count - 1;
            if retry_count <= 0 {
                break;
            }

            // try to recreate ssl stream
			let apns_url_production = "gateway.push.apple.com";
			let apns_url_development = "gateway.sandbox.push.apple.com";
			let apns_port = 2195;
			
			let apns_url = if self.sandbox {
				apns_url_development
			}
			else {
				apns_url_production
			};
			
			let ssl_result = get_ssl_stream(apns_url, apns_port, &self.certificate, &self.private_key, &self.ca_certificate);
			
			let mut borrow_ssl_stream = self.ssl_stream.borrow_mut();
			
			*borrow_ssl_stream = match ssl_result {
				Ok(ssl_stream) => {
					ssl_stream
				},
				Err(error) => {
                    println!("failed to get_ssl_stream error {:?}", error);
                    continue; 
				}
			};			

		}
		
		// Response error code
/*
		let mut read_buffer = [0u8; 6];
		println!("SslStream read {:?}", self.ssl_stream.read(&mut read_buffer));

		for c in read_buffer.iter() {
			print!("{}", c);
		}
		println!("");
*/
	}
}

fn get_ssl_stream(url: &str, port: u16, cert_file: &Path, private_key_file: &Path, ca_file: &Path) -> Result<SslStream<TcpStream>, SslError> {
	let mut context = match ssl::SslContext::new(ssl::SslMethod::Sslv23) {
		Ok(ctx) => {
			ctx
		},
		Err(error) => {
			panic!("SslContext new error {:?}", error);
		}
	};
	if let Some(error) = context.set_CA_file(&ca_file) {
		println!("set_CA_file error {:?}", error);
	}
	if let Some(error) = context.set_certificate_file(&cert_file, openssl::x509::X509FileType::PEM) {
		println!("set_certificate_file error {:?}", error);
	}
	if let Some(error) = context.set_private_key_file(&private_key_file, openssl::x509::X509FileType::PEM) {
		println!("set_private_key_file error {:?}", error);
	}

	let apns_ip = match net::addrinfo::get_host_addresses(url) {
		Ok(results) => {
			results[0]
		},
		Err(error) => {
			panic!("unable to resolve host address: {:?}", error);
		}
	};

	let sock_addr = SocketAddr{ip: apns_ip, port: port};
    let tcp_conn = TcpStream::connect(sock_addr).unwrap();
	let ssl = match ssl::Ssl::new(&context) {
		Ok(conn) => {
			conn
		},
		Err(error) => {
			panic!("Ssl new error {:?}", error);
		}
	};

	return SslStream::new_from(ssl, tcp_conn);
}

