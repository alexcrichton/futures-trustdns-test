// based on https://github.com/jcsoo/tokio-test

extern crate futures;
#[macro_use]
extern crate futures_io;
extern crate futures_mio;
extern crate trust_dns;

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;

use futures::{Future, oneshot, Complete, BoxFuture, Poll};
use trust_dns::op::Message;
use futures_mio::{Loop, LoopHandle, Sender, Receiver, UdpSocket};

fn print_response(m: Message) {
    println!("{}", m.get_queries()[0].get_name());
    for a in m.get_answers() {
        println!("  {:?}: {:?}", a.get_rr_type(), a.get_rdata());
    }
}

fn main() {
    let mut lp = Loop::new().unwrap();

    let resolver = resolver("8.8.8.8:53".parse().unwrap(), lp.handle());

    let r1 = resolver.lookup("google.com").map(print_response);
    let r2 = resolver.lookup("amazon.com").map(print_response);
    let r3 = resolver.lookup("apple.com").map(print_response);

    lp.run(r1.join3(r2, r3)).unwrap();
}

fn resolver(addr: SocketAddr, handle: LoopHandle) -> ResolverHandle {
    let (tx, rx) = handle.clone().channel();
    let socket = handle.udp_bind(&"0.0.0.0:0".parse().unwrap());

    socket.join(rx).and_then(move |(socket, rx)| {
        Resolver {
            addr: addr,
            socket: socket,
            rx: rx,
            rx_done: false,
            requests: HashMap::new(),
            queue: VecDeque::new(),
            buf: Vec::new(),
        }
    }).forget();

    ResolverHandle { tx: tx }
}

struct Resolver {
    addr: SocketAddr,
    socket: UdpSocket,
    queue: VecDeque<Message>,
    buf: Vec<u8>,
    rx: Receiver<(Message, Complete<io::Result<Message>>)>,
    rx_done: bool,
    requests: HashMap<u16, Complete<io::Result<Message>>>,
}

#[derive(Clone)]
pub struct ResolverHandle {
    tx: Sender<(Message, Complete<io::Result<Message>>)>,
}

impl ResolverHandle {
    pub fn lookup(&self, host: &str) -> BoxFuture<Message, io::Error> {
        let (tx, rx) = oneshot();
        let msg = query::build_query_message(query::any_query(&host));
        self.tx.send((msg, tx)).unwrap();
        rx.then(|res| {
            match res {
                Ok(r) => r,
                Err(_e) => panic!("canceled!"),
            }
        }).boxed()
    }
}

pub fn next_request_id() -> u16 {
    use std::sync::atomic::{AtomicUsize, ATOMIC_USIZE_INIT, Ordering};
    static DNS_REQ_ID: AtomicUsize = ATOMIC_USIZE_INIT;

    DNS_REQ_ID.fetch_add(1, Ordering::Relaxed) as u16
}

impl Future for Resolver {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        // Dequeue any new DNS resolution requests that we've got.
        //
        // For each new message we assign it an id, and then add it to our queue
        // of messages to write out.
        while !self.rx_done {
            match self.rx.recv() {
                Poll::Ok((mut msg, c)) => {
                    let id = msg.id(next_request_id()).get_id();
                    self.queue.push_back(msg);
                    self.requests.insert(id, c);
                }
                Poll::Err(_) => self.rx_done = true,
                Poll::NotReady => break,
            }
        }

        // Write all new requests to the name server we're using.
        while let Some(msg) = self.queue.pop_front() {
            self.buf.clear();
            query::encode_message(&mut self.buf, &msg);
            match self.socket.send_to(&self.buf, &self.addr) {
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.queue.push_front(msg);
                    break
                }
                Err(e) => {
                    self.requests.remove(&msg.get_id()).unwrap()
                        .complete(Err(e));
                }
            }
        }

        // Check to see if any of our requests are no longer needed. If so we
        // can just drop the associated completion half.
        let mut canceled = Vec::new();
        for (&id, req) in self.requests.iter_mut() {
            if let Poll::Ok(()) = req.poll_cancel() {
                canceled.push(id);
            }
        }
        for id in canceled {
            self.requests.remove(&id);
        }

        // Read any responses from our socket, completing the associated
        // request if it's still around.
        let mut buf = [0u8; 2048];
        while self.requests.len() > 0 {
            try_nb!(self.socket.recv_from(&mut buf));
            let msg = query::decode_message(&buf);
            if let Some(c) = self.requests.remove(&msg.get_id()) {
                c.complete(Ok(msg));
            }
        }

        // If all our `ResolverHandle` instances have disappeared, we've written
        // all our pending requests, and all our requests have been answered,
        // then we're done. Otherwise we'll come back for more later.
        if self.rx_done && self.queue.len() == 0 {
            Poll::Ok(())
        } else {
            Poll::NotReady
        }
    }
}

mod query {
    use trust_dns::rr::domain::Name;
    use trust_dns::rr::dns_class::DNSClass;
    use trust_dns::rr::record_type::RecordType;
    use trust_dns::op::{Message, MessageType, OpCode, Query};
    use trust_dns::serialize::binary::{BinEncoder, BinDecoder, BinSerializable};

    pub fn any_query(host: &str) -> Query {
        let mut query = Query::new();

        let root = Name::root();
        let name = Name::parse(host, Some(&root)).unwrap();
        query.name(name).query_class(DNSClass::IN).query_type(RecordType::A);
        query
    }

    pub fn build_query_message(query: Query) -> Message {
        let mut msg: Message = Message::new();
        msg.message_type(MessageType::Query)
           .op_code(OpCode::Query)
           .recursion_desired(true);
        msg.add_query(query);
        msg
    }

    pub fn encode_message(buf: &mut Vec<u8>, msg: &Message) {
        let mut encoder = BinEncoder::new(buf);
        msg.emit(&mut encoder).unwrap();
    }

    pub fn decode_message(buf: &[u8]) -> Message {
        let mut decoder = BinDecoder::new(buf);
        Message::read(&mut decoder).unwrap()
    }
}
