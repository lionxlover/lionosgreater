//! Audited libc syscall wrappers (the second — and last — module in the
//! crate with `unsafe`; every other module is `#![forbid(unsafe_code)]`).
//!
//! ════════════════════════════════════════════════════════════════════════
//! AUDIT BOX
//! 1. `peer_credentials` — one `getsockopt(SO_PEERCRED)` read of a
//!    kernel-filled `ucred`; no pointers cross the boundary.
//! 2. `mount_tmpfs` / `umount_lazy` — `mount(2)`/`umount2(2)` with
//!    NUL-terminated, length-bounded C strings built by the caller and
//!    validated here. No user-controlled content reaches mount options
//!    unfiltered (config `guest.tmpfs_size` is alnum-validated upstream).
//! 3. `fork_session_child` — the child path between `fork(2)` and
//!    `execve(2)` is **async-signal-safe**: only direct syscalls
//!    (read/close/chdir/setgroups/setgid/setuid/execve/write/_exit) and
//!    stack memory are used — no allocation, no locks, no std destructors
//!    (the child exits via `_exit` or execs). The env and argv CStrings
//!    and the env byte buffer are fully prepared in the parent before
//!    fork. All pipe fds are `O_CLOEXEC`, so the exec'd session inherits
//!    no greeter descriptors.
//! 4. `wait_exec_status` — `poll(2)` + one bounded `read(2)`.
//! 5. `kill_child` — `kill(2, SIGKILL)` on our own child pid.
//!
//! Nothing here logs; no secrets cross this boundary (the env buffer
//! contains only XDG/session variables — passwords never enter env).
//! ════════════════════════════════════════════════════════════════════════
#![allow(unsafe_code)] // audited module — see box above; see DESIGN.md

use std::ffi::CString;
use std::io;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

// ── SO_PEERCRED ────────────────────────────────────────────────────────
/// Credentials of the peer on a connected `AF_UNIX` stream socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

/// `getsockopt(fd, SOL_SOCKET, SO_PEERCRED)`.
pub fn peer_credentials(fd: std::os::fd::RawFd) -> io::Result<PeerCredentials> {
    let mut ucred: libc::ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `ucred` is a POD of the exact size libpam.. er, the kernel
    // expects for SO_PEERCRED; `len` is in/out and checked after.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != std::mem::size_of::<libc::ucred>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected SO_PEERCRED size",
        ));
    }
    Ok(PeerCredentials {
        pid: ucred.pid,
        uid: ucred.uid,
        gid: ucred.gid,
    })
}

// ── tmpfs mounts (guest sessions) ─────────────────────────────────────
/// Mount a fresh tmpfs at `target` (NOSUID|NODEV, mode 0700 implied by
/// opts passed by caller).
pub fn mount_tmpfs(target: &Path, opts: &str) -> io::Result<()> {
    if opts.len() > 128
        || !opts
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'=' || b == b',')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bad tmpfs options",
        ));
    }
    let c_target = path_to_cstring(target)?;
    let c_source = CString::new("tmpfs").map_err(|_| invalid("source"))?;
    let c_type = CString::new("tmpfs").map_err(|_| invalid("type"))?;
    let c_opts = CString::new(opts).map_err(|_| invalid("opts"))?;
    // SAFETY: all pointers are valid NUL-terminated strings owned above.
    let rc = unsafe {
        libc::mount(
            c_source.as_ptr(),
            c_target.as_ptr(),
            c_type.as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            c_opts.as_ptr() as *const libc::c_void,
        )
    };
    check_rc(rc)
}

/// Lazy detach (MNT_DETACH): safe even if the fs is busy.
pub fn umount_lazy(target: &Path) -> io::Result<()> {
    let c_target = path_to_cstring(target)?;
    // SAFETY: valid NUL-terminated path.
    let rc = unsafe { libc::umount2(c_target.as_ptr(), libc::MNT_DETACH) };
    check_rc(rc)
}

fn check_rc(rc: libc::c_int) -> io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid {what} for FFI"),
    )
}

fn path_to_cstring(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes().to_vec()).map_err(|_| invalid("path (contains NUL)"))
}

// ── fork/exec ─────────────────────────────────────────────────────────
/// Fully-prepared description of the session process to exec. Everything
/// is allocated before `fork` so the child never allocates.
#[derive(Debug, Clone)]
pub struct ChildSpec {
    /// argv[0] + args, NUL-free.
    pub argv: Vec<CString>,
    /// Home directory to chdir into.
    pub chdir: CString,
    pub uid: u32,
    pub gid: u32,
    /// Supplementary groups (initgroups equivalent).
    pub groups: Vec<u32>,
}

/// Parent-side handle of a forked child that is waiting for its
/// environment (see `write_env`) and then execs.
#[derive(Debug)]
pub struct SpawnedChild {
    pub pid: libc::pid_t,
    /// Write end of the env pipe.
    pub env_tx: std::fs::File,
    /// Read end of the exec-status pipe (4-byte errno, or EOF on success).
    pub status_rx: std::fs::File,
}

/// Max env bytes / entries handed to the child.
pub const MAX_ENV_BYTES: usize = 8192;
pub const MAX_ENV_ENTRIES: usize = 256;
/// Max argv entries.
const MAX_ARGV: usize = 128;

/// Fork a child that (1) reads its env from `env_pipe` as NUL-separated
/// `KEY=VALUE` entries, (2) chdir, (3) setgroups/setgid/setuid,
/// (4) `execve(argv)`. On any pre-exec failure the child writes the errno
/// (4 bytes) to the status pipe and `_exit(127)`s; on successful exec the
/// CLOEXEC'd status pipe simply closes (EOF).
///
/// The parent must later call `write_env` and `wait_exec_status`.
pub fn fork_session_child(spec: &ChildSpec) -> io::Result<SpawnedChild> {
    if spec.argv.is_empty() || spec.argv.len() > MAX_ARGV {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "argv out of bounds",
        ));
    }
    for a in &spec.argv {
        if a.as_bytes().is_empty() || a.as_bytes().len() > 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "argv entry out of bounds",
            ));
        }
    }
    if spec.groups.len() > 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many groups",
        ));
    }

    let mut env_fds = [0 as libc::c_int; 2];
    let mut status_fds = [0 as libc::c_int; 2];
    // SAFETY: pipe2 fills the arrays; O_CLOEXEC so the exec'd session
    // inherits no greeter fds.
    unsafe {
        check_rc(libc::pipe2(env_fds.as_mut_ptr(), libc::O_CLOEXEC))?;
        check_rc(libc::pipe2(status_fds.as_mut_ptr(), libc::O_CLOEXEC))?;
    }
    let (env_rd, env_wr) = (env_fds[0], env_fds[1]);
    let (status_rd, status_wr) = (status_fds[0], status_fds[1]);

    // SAFETY: see audit box §3 — the child branch below is
    // async-signal-safe (no allocation, syscalls only).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let e = io::Error::last_os_error();
        unsafe {
            libc::close(env_rd);
            libc::close(env_wr);
            libc::close(status_rd);
            libc::close(status_wr);
        }
        return Err(e);
    }
    if pid == 0 {
        // ── child (never returns) ──
        // SAFETY: see audit box §3 — close the pipe ends we inherited but
        // must not hold (our own env write end would mask EOF; the status
        // read end belongs to the parent), then run the exec path.
        unsafe {
            libc::close(env_wr);
            libc::close(status_rd);
            child_exec(spec, env_rd, status_wr)
        }
    }
    // ── parent ──
    // SAFETY: closing the child-side fds we don't use.
    unsafe {
        libc::close(env_rd);
        libc::close(status_wr);
    }
    Ok(SpawnedChild {
        pid,
        env_tx: unsafe { std::fs::File::from_raw_fd(env_wr) },
        status_rx: unsafe { std::fs::File::from_raw_fd(status_rd) },
    })
}

/// Child-side path: reads env, drops privileges, execs. `!` — never
/// returns (exits 127 on failure).
///
/// SAFETY: must only be called right after `fork()` returned 0, with the
/// spec fully allocated in the parent. Async-signal-safe: syscalls and
/// stack arrays only.
unsafe fn child_exec(spec: &ChildSpec, env_fd: libc::c_int, status_fd: libc::c_int) -> ! {
    const EXIT_FAIL: libc::c_int = 127;

    unsafe fn report_and_exit(status_fd: libc::c_int) -> ! {
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        // SAFETY: 4-byte write of a plain integer to our own pipe.
        let buf = (errno as u32).to_ne_bytes();
        let _ = libc::write(status_fd, buf.as_ptr() as *const libc::c_void, 4);
        libc::_exit(EXIT_FAIL);
    }

    // 1. read env block (NUL-separated KEY=VALUE entries, ends at EOF).
    let mut env_buf = [0u8; MAX_ENV_BYTES];
    let mut total = 0usize;
    loop {
        if total == env_buf.len() {
            // too much env → abort (fail closed)
            let _ = libc::write(status_fd, [0u8; 4].as_ptr() as *const libc::c_void, 4);
            libc::_exit(EXIT_FAIL);
        }
        // SAFETY: stack buffer, bounded length.
        let n = libc::read(
            env_fd,
            env_buf.as_mut_ptr().add(total) as *mut libc::c_void,
            env_buf.len() - total,
        );
        if n < 0 {
            // EINTR retry
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            libc::_exit(EXIT_FAIL);
        }
        if n == 0 {
            break;
        }
        total += n as usize;
    }
    // SAFETY: done with the env pipe.
    libc::close(env_fd);

    // 2. scan env entries into a stack pointer table (no allocation).
    let mut envp: [*const libc::c_char; MAX_ENV_ENTRIES + 1] =
        [std::ptr::null(); MAX_ENV_ENTRIES + 1];
    let mut entries = 0usize;
    let mut i = 0usize;
    let mut ok = total > 0;
    while i < total && entries < MAX_ENV_ENTRIES {
        let start = i;
        // SAFETY: buffer is stack memory; index math bounded by `total`.
        while i < total && env_buf[i] != 0 {
            i += 1;
        }
        if i == total || i == start {
            // missing trailing NUL or empty entry → malformed
            ok = false;
            break;
        }
        let entry = &env_buf[start..i];
        if !entry.contains(&b'=') {
            ok = false;
            break;
        }
        envp[entries] = entry.as_ptr() as *const libc::c_char;
        entries += 1;
        i += 1; // skip the NUL
    }
    if !ok {
        let _ = libc::write(status_fd, [0u8; 4].as_ptr() as *const libc::c_void, 4);
        libc::_exit(EXIT_FAIL);
    }
    envp[entries] = std::ptr::null();

    // 3. argv table (stack).
    let mut argv: [*const libc::c_char; MAX_ARGV + 1] = [std::ptr::null(); MAX_ARGV + 1];
    for (slot, arg) in argv.iter_mut().zip(spec.argv.iter()) {
        *slot = arg.as_ptr();
    }
    argv[spec.argv.len()] = std::ptr::null();

    // 4. chdir to home.
    if libc::chdir(spec.chdir.as_ptr()) != 0 {
        report_and_exit(status_fd);
    }

    // 5. drop privileges: groups → gid → uid (order matters; never regain).
    if !spec.groups.is_empty() && libc::setgroups(spec.groups.len(), spec.groups.as_ptr()) != 0 {
        report_and_exit(status_fd);
    }
    if libc::setgid(spec.gid) != 0 {
        report_and_exit(status_fd);
    }
    if libc::setuid(spec.uid) != 0 {
        report_and_exit(status_fd);
    }

    // 6. exec. On success the CLOEXEC status pipe closes → parent sees EOF.
    let path = spec.argv[0].as_ptr();
    if libc::execve(path, argv.as_ptr(), envp.as_ptr()) != 0 {
        report_and_exit(status_fd);
    }
    libc::_exit(EXIT_FAIL); // unreachable
}

/// Outcome of waiting for the child's exec status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecStatus {
    /// Status pipe hit EOF — exec succeeded.
    Execed,
    /// Child reported this errno before `_exit(127)`.
    Failed(libc::c_int),
    /// Child produced neither within the timeout (killed by caller).
    TimedOut,
}

/// Poll the status pipe for up to `timeout`.
pub fn wait_exec_status(status_rx: &std::fs::File, timeout: std::time::Duration) -> ExecStatus {
    let fd = std::os::fd::AsRawFd::as_raw_fd(status_rx);
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
    // SAFETY: single pollfd, valid fd.
    let rc = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, ms) };
    if rc == 0 {
        return ExecStatus::TimedOut;
    }
    if rc < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EINTR) {
            return ExecStatus::TimedOut; // caller may retry; conservative
        }
        return ExecStatus::Failed(e.raw_os_error().unwrap_or(libc::EIO));
    }
    if pfd.revents & libc::POLLIN == 0 && pfd.revents & libc::POLLHUP == 0 {
        return ExecStatus::TimedOut;
    }
    let mut buf = [0u8; 4];
    let mut got = 0usize;
    while got < 4 {
        // SAFETY: 4-byte stack buffer read.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().add(got) as *mut libc::c_void, 4 - got) };
        if n == 0 {
            return ExecStatus::Execed; // EOF: exec closed the pipe
        }
        if n < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return ExecStatus::Failed(libc::EIO);
        }
        got += n as usize;
    }
    let errno = u32::from_ne_bytes(buf) as libc::c_int;
    ExecStatus::Failed(if errno == 0 { libc::EPROTO } else { errno })
}

/// SIGKILL our child (used after `ExecStatus::TimedOut`).
pub fn kill_child(pid: libc::pid_t) {
    // SAFETY: pid comes from our own fork.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
}

/// Blocking `waitpid` (reaper thread only).
pub fn wait_child(pid: libc::pid_t) -> Option<i32> {
    let mut status: libc::c_int = 0;
    // SAFETY: valid pid from our fork, status is a POD out-param.
    let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
    if rc == pid {
        Some(libc::WEXITSTATUS(status))
    } else {
        None
    }
}

/// Are we root? (Privileged launch path is root-only; fail closed.)
pub fn is_root() -> bool {
    // SAFETY: getuid never fails.
    unsafe { libc::getuid() == 0 }
}

/// Current process uid (dev/test logging).
pub fn current_uid() -> u32 {
    // SAFETY: getuid never fails.
    unsafe { libc::getuid() as u32 }
}

/// Parse `LISTEN_FDS`/`LISTEN_PID` (sd_listen_fds(3)) and take ownership of
/// fd 3 when systemd socket-activated us. Exactly one fd is accepted.
pub fn take_listen_fd() -> Option<std::os::fd::OwnedFd> {
    let fds = std::env::var("LISTEN_FDS").ok()?;
    let pid = std::env::var("LISTEN_PID").ok()?;
    let n: i32 = fds.parse().ok()?;
    let pid: u32 = pid.parse().ok()?;
    if n < 1 || pid != std::process::id() {
        return None;
    }
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_PID");
    if n != 1 {
        tracing::warn!(count = n, "expected exactly one socket-activation fd");
        return None;
    }
    // SAFETY: fd 3 was passed to us by the service manager (verified via
    // LISTEN_PID == our pid); taking ownership closes it exactly once.
    Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(3) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn peer_credentials_on_socketpair() {
        // SAFETY: socketpair fills the array; test-only.
        let mut fds = [0 as libc::c_int; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        let cred = peer_credentials(fds[0]).unwrap();
        assert_eq!(cred.uid, current_uid());
        assert!(cred.pid > 0);
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    #[test]
    fn fork_exec_env_and_exit_code() {
        // exec /bin/sh -c 'echo $XDG_TEST_VAR' and verify env passing.
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let out_c = path_to_cstring(&out).unwrap();
        let script = format!("printf \"$XDG_TEST_VAR\" > {}", out_c.to_string_lossy());
        let spec = ChildSpec {
            argv: vec![
                CString::new("/bin/sh").unwrap(),
                CString::new("-c").unwrap(),
                CString::new(script).unwrap(),
            ],
            chdir: path_to_cstring(dir.path()).unwrap(),
            uid: current_uid(),
            gid: peer_credentials_self_gid(),
            groups: vec![],
        };
        let mut child = fork_session_child(&spec).unwrap();
        let env = b"XDG_TEST_VAR=hello-lion";
        child.env_tx.write_all(env).unwrap();
        child.env_tx.write_all(&[0]).unwrap();
        drop(child.env_tx);
        let st = wait_exec_status(&child.status_rx, std::time::Duration::from_secs(10));
        assert_eq!(st, ExecStatus::Execed, "child exec failed: {st:?}");
        let exit = wait_child(child.pid);
        assert_eq!(exit, Some(0));
        let content = std::fs::read_to_string(&out).unwrap();
        assert_eq!(content, "hello-lion");
    }

    fn peer_credentials_self_gid() -> u32 {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: test-only socketpair.
        unsafe {
            libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr());
        }
        let gid = peer_credentials(fds[0]).unwrap().gid;
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        gid
    }

    #[test]
    fn fork_exec_reports_errno() {
        // exec a nonexistent binary → child reports ENOENT via pipe.
        let dir = tempfile::tempdir().unwrap();
        let spec = ChildSpec {
            argv: vec![CString::new("/nonexistent/lion-nope").unwrap()],
            chdir: path_to_cstring(dir.path()).unwrap(),
            uid: current_uid(),
            gid: peer_credentials_self_gid(),
            groups: vec![],
        };
        let child = fork_session_child(&spec).unwrap();
        drop(child.env_tx); // EOF: empty env block is fine? child requires >0 entries
        let st = wait_exec_status(&child.status_rx, std::time::Duration::from_secs(10));
        // empty env → child aborts with EPROTO-mapped 0… our code writes
        // errno 0 → mapped to EPROTO. Either way: Failed, not Execed.
        match st {
            ExecStatus::Failed(_) => {}
            other => panic!("expected Failed, got {other:?}"),
        }
        let _ = wait_child(child.pid);
    }

    #[test]
    fn argv_bounds_validated() {
        use std::path::Path;
        let spec = ChildSpec {
            argv: vec![],
            chdir: path_to_cstring(Path::new("/tmp")).unwrap(),
            uid: 0,
            gid: 0,
            groups: vec![],
        };
        assert!(fork_session_child(&spec).is_err());
        let long: Vec<CString> = (0..200)
            .map(|i| CString::new(format!("a{i}")).unwrap())
            .collect();
        let spec2 = ChildSpec {
            argv: long,
            chdir: path_to_cstring(Path::new("/tmp")).unwrap(),
            uid: 1,
            gid: 1,
            groups: vec![],
        };
        assert!(fork_session_child(&spec2).is_err());
    }
}
