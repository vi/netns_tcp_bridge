use std::{
    io::{IoSlice, IoSliceMut},
    net::SocketAddr,
    os::unix::prelude::{FromRawFd, RawFd},
    path::PathBuf,
    time::Duration,
};

use anyhow::bail;
use either::Either;
use gumdrop::Options;
use nix::{
    cmsg_space,
    fcntl::{self, OFlag},
    sched::{setns, CloneFlags},
    sys::{
        socket::{
            accept, bind, listen, recvmsg, sendmsg, setsockopt, socket, socketpair,
            sockopt::ReuseAddr, AddressFamily, ControlMessage, MsgFlags, SockFlag, SockProtocol,
            SockType, SockaddrStorage,
        },
        stat::Mode,
        wait::waitpid,
    },
    unistd::{close, fork, ForkResult},
};

#[derive(Options)]
struct Opts {
    help: bool,

    /// Socket address (e.g. `127.0.0.1:1234` or `[::1]:1234`) to bind socket to.
    #[options(short = 'l')]
    listen: Option<SocketAddr>,

    /// File descriptor to use as a listening socket
    #[options(short = 'L')]
    listen_fd: Option<u64>,

    /// File descriptor to use as a single connected client (skip listening and accepting loop)
    #[options(short = 'S')]
    preaccepted_fd: Option<u64>,

    /// Socket address to forward incoming connections to.
    #[options(short = 'c')]
    connect: Option<SocketAddr>,

    /// Pre-connected file descriptor to forward just one accepted connection to
    #[options(short = 'C')]
    connect_fd: Option<u64>,

    /// Path to a nsfs file with mounted network namespace where listening part of the forwarder should operate. E.g. /proc/1234/ns/net
    #[options(short = 'f')]
    listen_netns_file: Option<PathBuf>,

    /// Already opened file descriptor to use for the `setns` call on listening side
    #[options(short = 'F')]
    listen_netns_fd: Option<u64>,

    /// Path to a nsfs netns file to `setns` on the connecting side
    #[options(short = 't')]
    connect_netns_file: Option<PathBuf>,

    /// Already opened file descriptor to use for  the `setns` call on the connecting side
    #[options(short = 'T')]
    connect_netns_fd: Option<u64>,
}

struct RawFdAutoClose(RawFd);

impl Drop for RawFdAutoClose {
    fn drop(&mut self) {
        if self.0 != -1 {
            let _ = close(self.0);
        }
    }
}

impl RawFdAutoClose {
    fn into_inner(mut self) -> RawFd {
        let ret = self.0;
        self.0 = -1;
        ret
    }
}

struct Opts2 {
    no_accept: bool,
    oneshot: bool,
    listen: Either<SocketAddr, RawFd>,
    listen_ns: Option<RawFd>,
    connect: Either<SocketAddr, RawFd>,
    connect_ns: Option<RawFd>,
}

struct OptsPart {
    no_accept: bool,
    oneshot: bool,
    socketpair_part: RawFd,
    sa_or_fd: Either<SocketAddr, RawFdAutoClose>,
    ns: Option<RawFdAutoClose>,
}

impl Opts {
    fn interpret(&self) -> anyhow::Result<Opts2> {
        let mut listen_specifiers = 0;
        let mut no_need_for_listen_netns = false;

        let mut listen = None;
        let mut listen_ns = None;
        let mut connect = None;
        let mut connect_ns = None;
        let mut no_accept = false;
        let mut oneshot = false;

        if let Some(sa) = self.listen {
            listen_specifiers += 1;
            listen = Some(Either::Left(sa));
        }
        if let Some(fd) = self.listen_fd {
            listen_specifiers += 1;
            no_need_for_listen_netns = true;
            listen = Some(Either::Right(RawFd::try_from(fd)?));
        }
        if let Some(fd) = self.preaccepted_fd {
            listen_specifiers += 1;
            no_need_for_listen_netns = true;
            no_accept = true;
            oneshot = true;
            listen = Some(Either::Right(RawFd::try_from(fd)?));
        }

        if listen_specifiers != 1 {
            bail!("Specify exactly one of -l, -L or -S");
        }

        let mut listen_netns_specifiers = 0;
        if let Some(ref path) = self.listen_netns_file {
            listen_netns_specifiers += 1;
            listen_ns = Some(fcntl::open(path, OFlag::O_RDONLY, Mode::all())?);
        }
        if let Some(fd) = self.listen_netns_fd {
            listen_netns_specifiers += 1;
            listen_ns = Some(RawFd::try_from(fd)?);
        }

        if listen_netns_specifiers > 1 {
            bail!("Cannot specify both -f and -F simultaneously")
        }

        if listen_netns_specifiers > 0 && no_need_for_listen_netns {
            bail!("Listening-side network namespace is not relevant with -L or -S")
        }

        let mut connect_specifiers = 0;
        let mut no_need_for_connect_netns = false;

        if let Some(sa) = self.connect {
            connect_specifiers += 1;
            connect = Some(Either::Left(sa));
        }
        if let Some(fd) = self.connect_fd {
            connect_specifiers += 1;
            no_need_for_connect_netns = true;
            connect = Some(Either::Right(RawFd::try_from(fd)?));
        }

        if connect_specifiers != 1 {
            bail!("Specify exactly one of -c or -C");
        }

        let mut connect_netns_specifiers = 0;
        if let Some(ref path) = self.connect_netns_file {
            connect_netns_specifiers += 1;
            connect_ns = Some(fcntl::open(path, OFlag::O_RDONLY, Mode::all())?);
        }
        if let Some(fd) = self.connect_netns_fd {
            connect_netns_specifiers += 1;
            connect_ns = Some(RawFd::try_from(fd)?);
        }

        if connect_netns_specifiers > 1 {
            bail!("Cannot specify both -t and -T simultaneously")
        }

        if connect_netns_specifiers > 0 && no_need_for_connect_netns {
            bail!("Connecting-side network namespace is not relevant with -C")
        }

        if listen_netns_specifiers == 0 && connect_netns_specifiers == 0 {
            eprintln!("No network-namespace-related option specified. Operating in a usual boring TCP forwarder mode.")
        }

        let listen = listen.unwrap();
        let connect = connect.unwrap();

        Ok(Opts2 {
            listen,
            listen_ns,
            connect,
            connect_ns,
            no_accept,
            oneshot,
        })
    }
}

impl Opts2 {
    fn split(self) -> anyhow::Result<(OptsPart, OptsPart)> {
        let (listen_part, connect_part) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::empty(),
        )?;

        Ok((
            OptsPart {
                no_accept: self.no_accept,
                oneshot: self.oneshot,
                socketpair_part: listen_part,
                sa_or_fd: self.listen.map_right(RawFdAutoClose),
                ns: self.listen_ns.map(RawFdAutoClose),
            },
            OptsPart {
                no_accept: self.no_accept,
                oneshot: self.oneshot,
                socketpair_part: connect_part,
                sa_or_fd: self.connect.map_right(RawFdAutoClose),
                ns: self.connect_ns.map(RawFdAutoClose),
            },
        ))
    }
}

impl OptsPart {
    fn listen(self) -> anyhow::Result<()> {
        if self.no_accept {
            assert!(self.oneshot);
            let fd = match self.sa_or_fd {
                Either::Left(_) => unreachable!(),
                Either::Right(fd) => fd.into_inner(),
            };
            let ret = sendmsg::<()>(
                self.socketpair_part,
                &[IoSlice::new(b"S")],
                &[ControlMessage::ScmRights(&[fd])],
                MsgFlags::empty(),
                None,
            )?;
            assert_eq!(ret, 1);
            return Ok(());
        }

        if let Some(ns) = self.ns {
            setns(ns.0, CloneFlags::CLONE_NEWNET)?;
        }

        let listen_socket = match self.sa_or_fd {
            Either::Left(sa) => {
                let af = match sa {
                    SocketAddr::V4(_) => AddressFamily::Inet,
                    SocketAddr::V6(_) => AddressFamily::Inet6,
                };
                let s = socket(af, SockType::Stream, SockFlag::empty(), SockProtocol::Tcp)?;
                setsockopt(s, ReuseAddr, &true)?;
                bind(s, &SockaddrStorage::from(sa))?;
                listen(s, if self.oneshot { 1 } else { 16 })?;
                s
            }
            Either::Right(fd) => fd.into_inner(),
        };

        loop {
            let s = accept(listen_socket);
            let s = match s {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error accepting: {}", e);
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
            };

            let ret = sendmsg::<()>(
                self.socketpair_part,
                &[IoSlice::new(b"S")],
                &[ControlMessage::ScmRights(&[s])],
                MsgFlags::empty(),
                None,
            )?;
            assert_eq!(ret, 1);
        }
    }

    fn connect(self) -> anyhow::Result<()> {
        if let Some(ns) = self.ns {
            setns(ns.0, CloneFlags::CLONE_NEWNET)?;
        }

        let mut cmsg = cmsg_space!([RawFd; 1]);

        let (tx, rx) = flume::bounded(if self.oneshot { 1 } else { 16 });
        let mut rx = Some(rx);

        if !self.oneshot {
            let sa = match self.sa_or_fd {
                Either::Left(sa) => sa,
                Either::Right(_fd) => unreachable!(),
            };
            // Note: `fork(2)` is used before that. Be careful when refactoring.
            let rx = rx.take().unwrap();
            std::thread::spawn(move || {
                if let Err(e) = forwarder(rx, Either::Left(sa)) {
                    eprintln!("Error: {}", e);
                }
            });
        }

        loop {
            let mut b = [0u8; 1];
            let ret = recvmsg::<()>(
                self.socketpair_part,
                &mut [IoSliceMut::new(&mut b)],
                Some(&mut cmsg),
                MsgFlags::empty(),
            )?;
            if ret.bytes == 0 {
                break;
            }
            assert_eq!(ret.bytes, 1);
            assert_eq!(b[0], b'S');
            let mut incoming_socket = None;
            for cmsg in ret.cmsgs() {
                match cmsg {
                    nix::sys::socket::ControlMessageOwned::ScmRights(r) => {
                        assert_eq!(r.len(), 1);
                        assert!(incoming_socket.is_none());
                        incoming_socket = Some(r[0]);
                    }
                    _ => panic!("Unhandled control message from socketpair"),
                }
            }
            let incoming_socket = incoming_socket.unwrap();

            match self.sa_or_fd {
                Either::Left(_) => (),
                Either::Right(fd) => {
                    assert!(self.oneshot);
                    tx.send(incoming_socket).unwrap();
                    drop(tx);
                    forwarder(rx.unwrap(), Either::Right(fd.into_inner()))?;
                    return Ok(());
                }
            };

            tx.send(incoming_socket)?;

            if self.oneshot {
                break;
            }
        }

        Ok(())
    }
}

fn forwarder(
    rx: flume::Receiver<RawFd>,
    sa_or_fd: Either<SocketAddr, RawFd>,
) -> anyhow::Result<()> {
    let mut b = tokio::runtime::Builder::new_current_thread();
    b.enable_io();
    let rt = b.build()?;

    match sa_or_fd {
        Either::Left(sa) => {
            rt.block_on(async move {
                loop {
                    let fd2 = rx.recv_async().await?;
                    // Safety: user-specified file descriptor. Assuming operator cares not to specify iffy values.
                    let tcp2 = unsafe { std::net::TcpStream::from_raw_fd(fd2) };
                    tcp2.set_nonblocking(true)?;
                    tcp2.set_nodelay(true)?;
                    let mut tcp2 = tokio::net::TcpStream::from_std(tcp2)?;

                    tokio::task::spawn(async move {
                        if let Err(e) = async move {
                            let mut tcp1 = tokio::net::TcpStream::connect(sa).await?;
                            let (_report1, _report2) =
                                tokio::io::copy_bidirectional(&mut tcp1, &mut tcp2).await?;
                            Ok::<_, anyhow::Error>(())
                        }
                        .await
                        {
                            eprintln!("Error connecting: {}", e);
                        }
                    });
                }

                #[allow(unreachable_code)]
                Ok::<_, anyhow::Error>(())
            })?;
        }
        Either::Right(fd) => {
            let fd2 = rx.recv()?;
            drop(rx);
            // Safety: user-specified file descriptor. Assuming operator cares not to specify iffy values.
            let tcp1 = unsafe { std::net::TcpStream::from_raw_fd(fd) };
            // Safety: result of `accept(2)` or a user-specific FD.
            let tcp2 = unsafe { std::net::TcpStream::from_raw_fd(fd2) };
            tcp1.set_nonblocking(true)?;
            tcp2.set_nonblocking(true)?;
            tcp1.set_nodelay(true)?;
            tcp2.set_nodelay(true)?;
            rt.block_on(async move {
                let mut tcp1 = tokio::net::TcpStream::from_std(tcp1)?;
                let mut tcp2 = tokio::net::TcpStream::from_std(tcp2)?;

                let (_report1, _report2) =
                    tokio::io::copy_bidirectional(&mut tcp1, &mut tcp2).await?;

                Ok::<_, anyhow::Error>(())
            })?;
        }
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let opts: Opts = gumdrop::parse_args_or_exit(gumdrop::ParsingStyle::AllOptions);

    let opts2 = opts.interpret()?;

    let (listen_opts, connect_opts) = opts2.split()?;

    // Safety: no multi-threaded things happening before this point, so should be OK.
    let fr = unsafe { fork()? };

    match fr {
        ForkResult::Parent { child } => {
            // listener
            close(connect_opts.socketpair_part)?;
            drop(connect_opts); // may close fds

            listen_opts.listen()?;

            waitpid(child, None)?;
        }
        ForkResult::Child => {
            // connector
            close(listen_opts.socketpair_part)?;
            drop(listen_opts); // may close fds

            connect_opts.connect()?;
        }
    }

    Ok(())
}
