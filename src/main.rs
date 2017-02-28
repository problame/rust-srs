extern crate getopts;
extern crate openssl;

mod srs;

use getopts::{Options,HasArg,Occur};
use openssl::hash::MessageDigest;

use std::env;

use std::net::*;
use std::io::{Read,Write};
use std::process;

use srs::parser::{SRSAddress};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {

    let args: Vec<String> = env::args().collect();

    let mut opts = Options::new();
    opts.opt("", "listen.recv", "listen for receivers", "", HasArg::Yes, Occur::Req);
    opts.opt("", "listen.send", "listen for receivers", "", HasArg::Yes, Occur::Req);
    opts.opt("s", "bufsize", "max buf size in bytes", "BYTES", HasArg::Yes, Occur::Req);

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            print_usage(&args[0], opts);
            process::exit(1);
        }
    };

    let listen_addr  = matches.opt_str("listen.recv").expect("required option not found");
    let listener = TcpListener::bind(listen_addr.as_str()).expect("specified listen addr must be bindable");

    for stream in listener.incoming() {
        match stream {
            Err(e) => {
                println!("Error accepting connection");
            },
            Ok(mut stream) => {
                println!("Connection from {:?}", stream.peer_addr());

                let mut buf = Vec::new();
                let mut bufsize: usize = matches.opt_str("bufsize").unwrap().parse().expect("bufsize must be an unsigned integer");
                buf.resize(bufsize, 0);

                let input = match stream.read(&mut buf) {
                    Err(e) => {
                        println!("error reading: {:?}", e);
                        continue;
                    },
                    Ok(len) => {
                        String::from_utf8_lossy(&buf[..len])
                    }
                };

                if !input.starts_with("get ") {
                    println!("invalid request format");
                    continue;
                }

                use srs::transformers::{Receiver,SRSTimestamper};
                let r = Receiver::new(
                    vec![0,0,0,0],
                    vec![0xb, 0xa, 0xd, 0xf, 0x0, 0x0, 0xd],
                    openssl::hash::MessageDigest::sha512(),
                    SRSTimestamper{max_valid_delta: 5},
                );
                let r = match r {
                    Err(x) => {
                        println!("cannot create receiver: {:?}", x);
                        continue;
                    },
                    Ok(r) => r,
                };


                let addr = SRSAddress::from_string(input[4..].trim_right());

                match addr {
                    Err(e) => {
                        println!("error parsing: {:?}", e);
                    },
                    Ok(a) => {
                        let res = r.receive(&a);
                        println!("SRS output: {:?}", res);
                    }
                }

                stream.shutdown(Shutdown::Both);
            }
        }

    }

}
