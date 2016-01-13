use std::cell::RefCell;
use std::rc::Rc;

use openssl::ssl;

struct StreamWrapper<S> {
    inner: Rc<RefCell<S>>,
}

impl<S> ::std::io::Read for StreamWrapper<S> where S: ::std::io::Read
{
    fn read(&mut self, buf: &mut [u8]) -> ::std::io::Result<usize> {
        self.inner.borrow_mut().read(buf)
    }
}

impl<S> ::std::io::Write for StreamWrapper<S> where S: ::std::io::Write
{
    fn write(&mut self, buf: &[u8]) -> ::std::io::Result<usize> {
        self.inner.borrow_mut().write(buf)
    }
    fn flush(&mut self) -> ::std::io::Result<()> {
        self.inner.borrow_mut().flush()
    }
}

pub struct SslStream<S: ::mio::Evented> {
    inner: Rc<RefCell<S>>,
    inner_ssl: ssl::SslStream<StreamWrapper<S>>,
}

impl<S> SslStream<S> where S: ::mio::Evented + ::std::io::Read + ::std::io::Write
{
    pub fn connect<T: ssl::IntoSsl>(ssl: T, stream: S) -> Result<Self, ssl::error::SslError> {
        let inner = Rc::new(RefCell::new(stream));
        let res = ssl::SslStream::connect(ssl, StreamWrapper { inner: inner.clone() });
        if let Err(e) = res {
            return Err(e);
        }

        Ok(SslStream {
            inner: inner,
            inner_ssl: res.unwrap(),
        })
    }

    pub fn accept<T: ssl::IntoSsl>(ssl: T, stream: S) -> Result<Self, ssl::error::SslError> {
        let inner = Rc::new(RefCell::new(stream));
        let res = ssl::SslStream::accept(ssl, StreamWrapper { inner: inner.clone() });
        if let Err(e) = res {
            return Err(e);
        }

        Ok(SslStream {
            inner: inner,
            inner_ssl: res.unwrap(),
        })
    }
}

impl<S> ::mio::Evented for SslStream<S> where S: ::mio::Evented
{
    fn register(&self,
                selector: &mut ::mio::Selector,
                token: ::mio::Token,
                interest: ::mio::EventSet,
                opts: ::mio::PollOpt)
                -> ::std::io::Result<()> {
        self.inner.borrow_mut().register(selector, token, interest, opts)
    }

    fn reregister(&self,
                  selector: &mut ::mio::Selector,
                  token: ::mio::Token,
                  interest: ::mio::EventSet,
                  opts: ::mio::PollOpt)
                  -> ::std::io::Result<()> {
        self.inner.borrow_mut().reregister(selector, token, interest, opts)
    }

    fn deregister(&self, selector: &mut ::mio::Selector) -> ::std::io::Result<()> {
        self.inner.borrow_mut().deregister(selector)
    }
}

fn convert_error(e: ssl::error::Error) -> ::std::io::Error {
    use std::io::{Error, ErrorKind};
    use openssl::ssl::error::Error::*;
    match e {
        WantRead(e) => e,
        WantWrite(e) => e,
        Stream(e) => e,
        _ => Error::new(ErrorKind::Other, ""),
    }
}

fn convert_ssl_error(e: ssl::error::SslError) -> ::std::io::Error {
    use std::io::{Error, ErrorKind};
    use openssl::ssl::error::SslError::*;
    match e {
        StreamError(e) => e,
        _ => Error::new(ErrorKind::Other, ""),
    }
}

impl<S> ::std::io::Read for SslStream<S>
    where S: ::std::io::Read + ::std::io::Write + ::mio::Evented
{
    fn read(&mut self, buf: &mut [u8]) -> ::std::io::Result<usize> {
        self.inner_ssl.ssl_read(buf).map_err(convert_error)
    }
}

impl<S> ::std::io::Write for SslStream<S>
    where S: ::std::io::Read + ::std::io::Write + ::mio::Evented
{
    fn write(&mut self, buf: &[u8]) -> ::std::io::Result<usize> {
        self.inner_ssl.ssl_write(buf).map_err(convert_error)
    }
    fn flush(&mut self) -> ::std::io::Result<()> {
        self.inner_ssl.flush()
    }
}

pub type Stream = ::gj::io::stream::Stream<SslStream<::mio::tcp::TcpStream>>;

struct SslListener {
    ssl_context: ssl::SslContext,
    inner: ::mio::tcp::TcpListener,
}

impl ::mio::Evented for SslListener {
    fn register(&self,
                selector: &mut ::mio::Selector,
                token: ::mio::Token,
                interest: ::mio::EventSet,
                opts: ::mio::PollOpt)
                -> ::std::io::Result<()> {
        self.inner.register(selector, token, interest, opts)
    }

    fn reregister(&self,
                  selector: &mut ::mio::Selector,
                  token: ::mio::Token,
                  interest: ::mio::EventSet,
                  opts: ::mio::PollOpt)
                  -> ::std::io::Result<()> {
        self.inner.reregister(selector, token, interest, opts)
    }

    fn deregister(&self, selector: &mut ::mio::Selector) -> ::std::io::Result<()> {
        self.inner.deregister(selector)
    }
}

impl ::mio::TryAccept for SslListener {
    type Output = SslStream<::mio::tcp::TcpStream>;

    fn accept(&self) -> ::std::io::Result<Option<Self::Output>> {
        let ssl = try!(ssl::Ssl::new(&self.ssl_context).map_err(convert_ssl_error));

        match try!(self.inner.accept()) {
            Some((tcp, _)) => {
                match SslStream::accept(ssl, tcp) {
                    Ok(stream) => Ok(Some(stream)),
                    Err(e) => Err(convert_ssl_error(e)),
                }
            }
            None => Ok(None),
        }
    }
}

pub type Listener = ::gj::io::stream::Listener<SslListener>;

pub trait BindSsl {
    fn bind(addr: ::std::net::SocketAddr, ssl_context: ssl::SslContext) -> Result<Listener, ::std::io::Error>;
}

pub fn bind_listener(addr: ::std::net::SocketAddr, ssl_context: ssl::SslContext)  -> Result<Listener, ::std::io::Error>{
    let inner = SslListener {
        ssl_context: ssl_context,
        inner: try!(::mio::tcp::TcpListener::bind(&addr)),
    };
    Ok(try!(Listener::new(inner)))
}
