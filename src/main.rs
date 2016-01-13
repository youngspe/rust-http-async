#[macro_use(pry)]
extern crate gj;
extern crate httparse;
extern crate openssl;
extern crate mio;

use std::io::Write;
use std::path::{Path, PathBuf};

use gj::Promise;
use gj::io::{AsyncRead, AsyncWrite};

use openssl::ssl;
use openssl::ssl::{SslContext, SslMethod, SSL_VERIFY_NONE};
use openssl::ssl::error::SslError;
use openssl::x509::X509FileType;

mod sslstream;

use sslstream::Listener;

struct Header {
    name: String,
    value: String,
}

impl Header {
    fn from_httparse(h: httparse::Header) -> Result<Header, HttpError> {

        let value = match std::str::from_utf8(h.value) {
            Ok(value) => value,
            Err(_) => return Result::Err(HttpError::ParseError(httparse::Error::HeaderValue)),
        };
        Ok(Header {
            name: h.name.to_string(),
            value: value.to_string(),
        })
    }
}

struct Request {
    pub method: String,
    pub path: String,
    pub version: u8,
    pub headers: Vec<Header>,
}

impl Request {
    fn from_httparse(r: httparse::Request) -> Result<Request, HttpError> {
        let mut headers = Vec::new();
        for h in r.headers {
            if h.name == "" {
                break;
            }
            headers.push(try!(Header::from_httparse(*h)));
        }
        if r.method == None || r.path == None {
            return Result::Err(HttpError::ParseError(httparse::Error::HeaderValue));
        }
        if r.version == None {
            return Result::Err(HttpError::ParseError(httparse::Error::Version));
        }
        Ok(Request {
            method: r.method.unwrap().to_string(),
            path: r.path.unwrap().to_string(),
            version: r.version.unwrap(),
            headers: headers,
        })
    }
}

fn socket_addr_v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> std::net::SocketAddr {
    use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};

    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
}

fn buf_ends_with<T>(buf: &[T], end: &[T]) -> bool
    where T: PartialEq<T>
{
    if end.len() > buf.len() {
        return false;
    }
    let start = buf.len() - end.len();
    for i in 0..end.len() {
        if buf[start + i] != end[i] {
            return false;
        }
    }
    true
}

fn remove_from_end<T>(vec: &mut Vec<T>, end: &[T]) -> bool
    where T: PartialEq<T>
{
    let len = vec.len();
    if buf_ends_with(vec, end) {
        vec.truncate(len - end.len());
        true
    } else {
        false
    }
}

fn read_from_headers<T>(req: &Request, name: &str) -> Option<T>
    where T: std::str::FromStr
{
    for h in &req.headers {
        if h.name == "" {
            return None;
        }
        if h.name.to_lowercase() == name.to_lowercase() {
            return h.value.parse().ok();
        }
    }
    None
}

fn read_n_bytes<R: AsyncRead, B: AsMut<[u8]> + AsRef<[u8]> + 'static>
    (src_stream: R,
     mut vec: Vec<u8>,
     buf: B,
     bytes_to_read: usize,
     mut bytes_read: usize)
     -> Promise<Vec<u8>, HttpError> {
    if bytes_read >= bytes_to_read {
        return Promise::ok(vec);
    };

    src_stream.try_read(buf, 1).then_else(move |r| {
        match r {
            Ok((src, buf, n)) => {
                if n == 0 {
                    // EOF
                    Promise::ok(vec)
                } else {
                    for b in &buf.as_ref()[0..n] {
                        vec.push(*b);
                        bytes_read += 1;
                    }
                    read_n_bytes(src, vec, buf, bytes_to_read, bytes_read)
                }
            }

            Err(gje) => Promise::err(HttpError::IoError(gje.error)),
        }
    })
}

const MAX_HEADERS: usize = 100;
#[derive(Debug)]
pub enum HttpError {
    IoError(std::io::Error),
    ParseError(httparse::Error),
    SslError(openssl::ssl::error::SslError),
    Partial,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, fmter: &mut std::fmt::Formatter) -> std::fmt::Result {
        use HttpError::*;
        match *self {
            IoError(ref e) => {
                try!(fmter.write_str("IoError: "));
                try!(fmter.write_str(&format!("{}", e)));
                Ok(())
            }
            ParseError(_) => {
                try!(fmter.write_str("ParseError: "));
                Ok(())
            }
            SslError(ref e) => {
                try!(fmter.write_str("IoError: "));
                try!(fmter.write_str(&format!("{}", e)));
                Ok(())
            }
            Partial => {
                try!(fmter.write_str("Partial"));
                Ok(())
            }
        }
    }
}

fn parse_headers<'b>(src: &'b [u8]) -> Result<Request, HttpError> {
    let mut h = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut h);
    let res = req.parse(src);
    match res {
        Ok(httparse::Status::Complete(_)) => Result::Ok(try!(Request::from_httparse(req))),
        Ok(httparse::Status::Partial) => Result::Err(HttpError::Partial),
        Err(error) => {
            match error {
                _ => Result::Err(HttpError::ParseError(error)),
            }
        }
    }
}

fn read_content<R: AsyncRead>(input: (R, Vec<u8>, Vec<u8>, usize))
                              -> Promise<(Request, Vec<u8>), HttpError> {
    let (src_stream, header_vec, vec, bytes_left) = input;

    let res = parse_headers(&header_vec);
    if let Result::Err(error) = res {
        return Promise::err(error);
    }
    let req = res.unwrap();

    let mut length = read_from_headers::<usize>(&req, "content-length").unwrap_or(0);
    length = std::cmp::max(length - bytes_left, 0);
    read_n_bytes(src_stream, vec, vec![0; 1024], length, 0).then(|vec| Promise::ok((req, vec)))
}

fn read_headers<R: AsyncRead, B: AsMut<[u8]> + AsRef<[u8]> + 'static>
    (src_stream: R,
     mut vec: Vec<u8>,
     buf: B)
     -> Promise<(R, Vec<u8>, Vec<u8>, usize), HttpError> {
    src_stream.try_read(buf, 1).then_else(move |r| {
        match r {
            Ok((src, buf, n)) => {
                if n == 0 {
                    // EOF
                    Promise::ok((src, vec, Vec::new(), 0))
                } else {
                    let mut bytes_read = 0;
                    for i in 0..n {
                        let b = buf.as_ref()[i];
                        vec.push(b);
                        bytes_read += 1;
                        if buf_ends_with(&mut vec, b"\r\n\r\n") ||
                           buf_ends_with(&mut vec, b"\n\n") {
                            // two blank lines == request is over
                            let mut left_over = Vec::new();
                            for j in (i + 1)..n {
                                let b = buf.as_ref()[j];
                                left_over.push(b);
                            }
                            return Promise::ok((src, vec, left_over, n - bytes_read));
                        }
                    }
                    read_headers(src, vec, buf)
                }
            }

            Err(gje) => Promise::err(HttpError::IoError(gje.error)),
        }
    })
}

fn read_request<R: AsyncRead>(src_stream: R) -> Promise<(Request, Vec<u8>), HttpError> {
    let buf = vec![0; 1024];
    read_headers(src_stream, Vec::new(), buf).then(read_content)
}

fn handle<R, W>(src_stream: R, dst_stream: W) -> Promise<(), HttpError>
    where R: AsyncRead,
          W: AsyncWrite
{
    println!("processing input...");
    read_request(src_stream)
        .then(|(req, body)| {
            println!("");
            println!("Request:");
            println!("Method: {}", req.method);
            println!("Path: {}", req.path);
            for h in req.headers {
                println!("{}: {}", h.name, h.value)
            }
            let body_string = std::str::from_utf8(&body).unwrap_or("Error: could not read body.");
            println!("Body:\n{}", body_string);

            let mut res = Vec::new();
            pry!(res.write(b"HTTP/1.1 200 OK\r\n")
                    .and_then(|_| res.write(b"Content-Type: text/html; charset=UTF-8\r\n"))
                    .and_then(|_| res.write(b"Content-Length: 13\r\n"))
                    .and_then(|_| res.write(b"Connection: close\r\n"))
                    .and_then(|_| res.write(b"\r\n"))
                    .and_then(|_| res.write(b"Hello, world!"))
                    .map_err(|e| HttpError::IoError(e)));

            dst_stream.write(res).map_err(|gje| HttpError::IoError(gje.error))

        })
        .then_else(|_| {
            // do nothing with the errors for now
            Promise::ok(())
        })
}

fn accept_loop(receiver: Listener,
               mut task_set: gj::TaskSet<(), HttpError>)
               -> Promise<(), std::io::Error> {
    receiver.accept().lift().then(move |(receiver, src_stream)| {
        println!("handling connection");

        let (src_reader, src_writer) = src_stream.split();
        task_set.add(handle(src_reader, src_writer));
        accept_loop(receiver, task_set)
    })
}

struct Reporter;

impl gj::TaskReaper<(), HttpError> for Reporter {
    fn task_failed(&mut self, error: HttpError) {
        println!("Task failed: {}", error);
    }
}

pub fn create_ssl_context<C, K>(cert: C, key: K) -> Result<SslContext, SslError>
        where C: AsRef<Path>, K: AsRef<Path> {
            let mut ctx = try!(SslContext::new(SslMethod::Sslv23));
            try!(ctx.set_cipher_list("DEFAULT"));
            try!(ctx.set_certificate_file(cert.as_ref(), X509FileType::PEM));
            try!(ctx.set_private_key_file(key.as_ref(), X509FileType::PEM));
            ctx.set_verify(SSL_VERIFY_NONE, None);
            Ok(ctx)
        }

fn main() {
    gj::EventLoop::top_level(|wait_scope| {
        let cert_path = PathBuf::from("./new.cert.crt");
        let key_path = PathBuf::from("./new.cert.key");
        let ctx = create_ssl_context(cert_path, key_path).unwrap();

        let listener = sslstream::bind_listener(socket_addr_v4(127, 0, 0, 1, 1337), ctx).unwrap();
        accept_loop(listener, gj::TaskSet::new(Box::new(Reporter))).lift().wait(wait_scope)
    })
        .unwrap();
}
