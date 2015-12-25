use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use rustc_serialize::Encodable;
use rustc_serialize::Encoder;
use rustc_serialize::json;

use openssl;
use openssl::ssl;
use openssl::ssl::SslStream;
use openssl::ssl::error::SslError;

use std::ops::{Range, Index};
use std::net::TcpStream;
use std::io::{Cursor, Read, Write};
use std::path::Path;
use std::vec::Vec;
use std::collections::HashMap;

use num::pow;
use rand::{self, Rng};
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
				let mut count = 1;
		        if badge.is_some() { count = count + 1; }
		        if sound.is_some() { count = count + 1; }
		        if content_available.is_some() { count = count + 1; }
	        
		        let mut index = 0usize;
				encoder.emit_struct("PayloadAPS", count, |encoder| {
					try!(encoder.emit_struct_field( "alert", index, |encoder| alert.encode(encoder)));
					index = index + 1;
					if badge.is_some() { 
						try!(encoder.emit_struct_field( "badge", index, |encoder| badge.unwrap().encode(encoder)));
						index = index + 1;
		            }
		            if sound.is_some() { 
						try!(encoder.emit_struct_field( "sound", index, |encoder| sound.unwrap().encode(encoder)));
						index = index + 1;
		            }
		            if content_available.is_some() { 
						try!(encoder.emit_struct_field( "content-available", index, |encoder| content_available.unwrap().encode(encoder)));
						index = index + 1;
		            }
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
    let mut n = hex.to_string().len();
    
    for c in hex.chars() {
        n = n - 1;
		match c {
		    '0'...'9' => {
				total += pow(16, n) * ((c as u32) - ('0' as u32));
		    },
		    'a'...'f' => {
				total += pow(16, n) * ((c as u32) - ('a' as u32) + 10);
		    },
		    _ => {
				
		    }
		}
    }
    
    return total;
}

#[allow(dead_code)]
fn convert_to_binary(device_token: &str) -> Vec<u8> {
    let mut device_token_bytes: Vec<u8> = Vec::new();
    for i in 0..8 {
		let string = device_token.to_string();
		let range = Range{start:i*8, end:i*8+8};
		let sub_str = string.index(range);
	
		let sub_str_num = hex_to_int(sub_str);
		let mut sub_str_bytes = vec![];
		let _ = sub_str_bytes.write_u32::<BigEndian>(sub_str_num);
	
        for s in sub_str_bytes.iter() {
            device_token_bytes.push(*s);
        }
    }
    
    return device_token_bytes;
}

#[allow(dead_code)]
pub fn convert_to_token(binary: &[u8]) -> String {
    let mut token = "".to_string();
    for i in 0..8 {
		let range = Range{start:i*4, end:i*4+4};
		let sub_slice = binary.index(range);
	
		let mut rdr = Cursor::new(sub_slice.to_vec());
		let num = rdr.read_u32::<BigEndian>().unwrap();
	
		token = format!("{}{:x}", token, num);
    }
    return token;
}

#[allow(dead_code)]
pub fn convert_to_timestamp(binary: &[u8]) -> u32 {
    let mut rdr = Cursor::new(binary.to_vec());
    let num = rdr.read_u32::<BigEndian>().unwrap();
    
    return num;
}

pub struct APNS<'a> {
    pub sandbox: bool,
    pub certificate: &'a Path,
    pub private_key: &'a Path,
    pub ca_certificate: &'a Path,
}

impl<'a> APNS<'a> {
    pub fn new(sandbox: bool, cert_file: &'a Path, private_key_file: &'a Path, ca_file: &'a Path) -> APNS<'a> {
		APNS{sandbox: sandbox, certificate: cert_file, private_key: private_key_file, ca_certificate: ca_file}
    }
    
    #[allow(dead_code)]
    pub fn get_feedback(&self) -> Result<Vec<(u32, String)>, SslError> {
		let apns_feedback_production = "feedback.push.apple.com:2196";
		let apns_feedback_development = "feedback.sandbox.push.apple.com:2196";
        
		let apns_feedback_url = if self.sandbox { apns_feedback_development } else { apns_feedback_production };
		let mut stream = try!(get_ssl_stream(apns_feedback_url, self.certificate, self.private_key, self.ca_certificate));

		let mut tokens: Vec<(u32, String)> = Vec::new();
        let mut read_buffer = [0u8; 38];
        loop {
            match stream.ssl_read(&mut read_buffer) {
                Ok(size) => {
                    if size != 38 {
                        break;
                    }
                },
                Err(..) => {
                    /*				return Result::Err(SslError::StreamError(error));*/
                    break;
                }
            }
		    let time_range = Range{start:0, end:4};
		    let time_slice = read_buffer.index(time_range);
		    let time = convert_to_timestamp(time_slice);
    
		    let token_range = Range{start:6, end:38};
		    let token_slice = read_buffer.index(token_range);
			
            let token = convert_to_token(token_slice);
			tokens.push((time, token));
        }

        return Result::Ok(tokens);
    }

    #[allow(dead_code)]
    pub fn send_payload(&self, payload: Payload, device_token: &str) {
        let notification_bytes = get_notification_bytes(payload, device_token);

        let apns_url_production = "gateway.push.apple.com:2195";
        let apns_url_development = "gateway.sandbox.push.apple.com:2195";
        
        let apns_url = if self.sandbox { apns_url_development } else { apns_url_production };
        
        let ssl_result = get_ssl_stream(apns_url, self.certificate, self.private_key, self.ca_certificate);
        match ssl_result {
            Ok(mut ssls) => {
                if let Err(error) = ssls.ssl_write(&notification_bytes) {
                    println!("ssl_stream write error {:?}", error); 
                }
				
				// Read possible error code response
				if ssls.ssl().pending() == 6 {
                    let mut read_buffer = [0u8; 6];
                    match ssls.ssl_read(&mut read_buffer) {
                        Ok(size) => {
                            for c in read_buffer.iter() {
                                print!("{}", c);
                            }
                            println!("ssl_stream read size {:?}", size);
                        }
                        Err(error) => {
                            println!("ssl_stream read error {:?}", error);
                        }
                    }
                }
            },
            Err(error) => {
                println!("failed to get_ssl_stream error {:?}", error);
            }
        };
    }
}

fn get_notification_bytes(payload: Payload, device_token: &str) -> Vec<u8> {
    let payload_str = match json::encode(&payload) {
        Ok(json_str) => { json_str.to_string() }
        Err(error) => {
            println!("json encode error {:?}", error);
            return vec![]; 
        }
    };

    let payload_bytes = payload_str.into_bytes();
    let device_token_bytes: Vec<u8> = convert_to_binary(device_token);

    let mut notification_buffer: Vec<u8> = vec![];
    let mut message_buffer: Vec<u8> = vec![];

    // Device token
    let mut device_token_length = vec![];
    let _ = device_token_length.write_u16::<BigEndian>(device_token_bytes.len() as u16);

    message_buffer.push(1u8);
    for s in device_token_length.iter() {
        message_buffer.push(*s);
    }
    for s in device_token_bytes.iter() {
        message_buffer.push(*s);
    }

    // Payload
    let mut payload_length = vec![];
    let _ = payload_length.write_u16::<BigEndian>(payload_bytes.len() as u16);

    message_buffer.push(2u8);
    for s in payload_length.iter() {
        message_buffer.push(*s);
    }
    for s in payload_bytes.iter() {
        message_buffer.push(*s);
    }

    // Notification identifier
    let payload_id = rand::thread_rng().gen();
    let mut payload_id_be = vec![];
    let _ = payload_id_be.write_u32::<BigEndian>(payload_id);

    let mut payload_id_length = vec![];
    let _ = payload_id_length.write_u16::<BigEndian>(payload_id_be.len() as u16);

    message_buffer.push(3u8);
    for s in payload_id_length.iter() {
        message_buffer.push(*s);
    }
    for s in payload_id_be.iter() {
        message_buffer.push(*s);
    }

    //	Expiration date
    let time = time::now().to_timespec().sec + 86400;	// expired after one day
    let mut exp_date_be = vec![];
    let _ = exp_date_be.write_u32::<BigEndian>(time as u32);

    let mut exp_date_length = vec![];
    let _ = exp_date_length.write_u16::<BigEndian>(exp_date_be.len() as u16);

    message_buffer.push(4u8);
    for s in exp_date_length.iter() {
        message_buffer.push(*s);
    }
    for s in exp_date_be.iter() {
        message_buffer.push(*s);
    }

    // Priority
    let mut priority_length = vec![];
    let _ = priority_length.write_u16::<BigEndian>(1u16);

    message_buffer.push(5u8);
    for s in priority_length.iter() {
        message_buffer.push(*s);
    }
    message_buffer.push(10u8);

    let mut message_buffer_length = vec![];
    let _ = message_buffer_length.write_u32::<BigEndian>(message_buffer.len() as u32);
    
    let command = 2u8;
    notification_buffer.push(command);
    for s in message_buffer_length.iter() {
        notification_buffer.push(*s);
    }
    for s in message_buffer.iter() {
        notification_buffer.push(*s);
    }
    
    return notification_buffer;
}

fn get_ssl_stream(url: &str, cert_file: &Path, private_key_file: &Path, ca_file: &Path) -> Result<SslStream<TcpStream>, SslError> {
    let mut context = try!(ssl::SslContext::new(ssl::SslMethod::Sslv23));
	let ssl = try!(ssl::Ssl::new(&context));
    
    if let Err(error) = context.set_CA_file(ca_file) {
		println!("set_CA_file error {:?}", error);
    }
    if let Err(error) = context.set_certificate_file(cert_file, openssl::x509::X509FileType::PEM) {
		println!("set_certificate_file error {:?}", error);
    }
    if let Err(error) = context.set_private_key_file(private_key_file, openssl::x509::X509FileType::PEM) {
		println!("set_private_key_file error {:?}", error);
    }

    let tcp_conn = match TcpStream::connect(url) {
		Ok(conn) => { conn },
		Err(error) => {
			println!("tcp_stream connect error {:?}", error);
			return Result::Err(SslError::StreamError(error));
		}
	};
	
	return SslStream::connect(ssl, tcp_conn);
}
