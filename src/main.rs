use libc::{c_void, user_regs_struct, PT_NULL};
use nix::sys::ptrace;
use nix::sys::ptrace::*;
use nix::sys::wait::waitpid;
use std::collections::HashMap;
use std::mem;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::ptr;
use std::io;
use std::io::prelude::*;
use std::time::Instant;

fn traceme() -> std::io::Result<(())> {
    match ptrace::traceme() {
        Ok(()) => Ok(()),
        Err(::nix::Error::Sys(errno)) => Err(std::io::Error::from_raw_os_error(errno as i32)),
        Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
    }
}

pub fn get_regs(pid: nix::unistd::Pid) -> Result<user_regs_struct, nix::Error> {
    unsafe {
        let mut regs: user_regs_struct = mem::uninitialized();

        #[allow(deprecated)]
        let res = ptrace::ptrace(
            Request::PTRACE_GETREGS,
            pid,
            PT_NULL as *mut c_void,
            &mut regs as *mut _ as *mut c_void,
        );
        res.map(|_| regs)
    }
}



fn pause() {

    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    // We want the cursor to stay at the end of the line, so we print without a newline and flush manually.
    write!(stdout, "Press any key to continue...").unwrap();
    stdout.flush().unwrap();

    // Read a single byte and discard
    let _ = stdin.read(&mut [0u8]).unwrap();
}

fn main() {
    let syscallNames : Vec<&str > = vec![
        "read",
        "write",
        "open",
        "close",
        "stat",
        "fstat",
        "lstat",
        "poll",
        "lseek",
        "mmap",
        "mprotect",
        "munmap",
        "brk",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "ioctl",
        "pread64",
        "pwrite64",
        "readv",
        "writev",
        "access",
        "pipe",
        "select",
        "sched_yield",
        "mremap",
        "msync",
        "mincore",
        "madvise",
        "shmget",
        "shmat",
        "shmctl",
        "dup",
        "dup2",
        "pause",
        "nanosleep",
        "getitimer",
        "alarm",
        "setitimer",
        "getpid",
        "sendfile",
        "socket",
        "connect",
        "accept",
        "sendto",
        "recvfrom",
        "sendmsg",
        "recvmsg",
        "shutdown",
        "bind",
        "listen",
        "getsockname",
        "getpeername",
        "socketpair",
        "setsockopt",
        "getsockopt",
        "clone",
        "fork",
        "vfork",
        "execve",
        "exit",
        "wait4",
        "kill",
        "uname",
        "semget",
        "semop",
        "semctl",
        "shmdt",
        "msgget",
        "msgsnd",
        "msgrcv",
        "msgctl",
        "fcntl",
        "flock",
        "fsync",
        "fdatasync",
        "truncate",
        "ftruncate",
        "getdents",
        "getcwd",
        "chdir",
        "fchdir",
        "rename",
        "mkdir",
        "rmdir",
        "creat",
        "link",
        "unlink",
        "symlink",
        "readlink",
        "chmod",
        "fchmod",
        "chown",
        "fchown",
        "lchown",
        "umask",
        "gettimeofday",
        "getrlimit",
        "getrusage",
        "sysinfo",
        "times",
        "ptrace",
        "getuid",
        "syslog",
        "getgid",
        "setuid",
        "setgid",
        "geteuid",
        "getegid",
        "setpgid",
        "getppid",
        "getpgrp",
        "setsid",
        "setreuid",
        "setregid",
        "getgroups",
        "setgroups",
        "setresuid",
        "getresuid",
        "setresgid",
        "getresgid",
        "getpgid",
        "setfsuid",
        "setfsgid",
        "getsid",
        "capget",
        "capset",
        "rt_sigpending",
        "rt_sigtimedwait",
        "rt_sigqueueinfo",
        "rt_sigsuspend",
        "sigaltstack",
        "utime",
        "mknod",
        "uselib",
        "personality",
        "ustat",
        "statfs",
        "fstatfs",
        "sysfs",
        "getpriority",
        "setpriority",
        "sched_setparam",
        "sched_getparam",
        "sched_setscheduler",
        "sched_getscheduler",
        "sched_get_priority_max",
        "sched_get_priority_min",
        "sched_rr_get_interval",
        "mlock",
        "munlock",
        "mlockall",
        "munlockall",
        "vhangup",
        "modify_ldt",
        "pivot_root",
        "_sysctl",
        "prctl",
        "arch_prctl",
        "adjtimex",
        "setrlimit",
        "chroot",
        "sync",
        "acct",
        "settimeofday",
        "mount",
        "umount2",
        "swapon",
        "swapoff",
        "reboot",
        "sethostname",
        "setdomainname",
        "iopl",
        "ioperm",
        "create_module",
        "init_module",
        "delete_module",
        "get_kernel_syms",
        "query_module",
        "quotactl",
        "nfsservctl",
        "getpmsg",
        "putpmsg",
        "afs_syscall",
        "tuxcall",
        "security",
        "gettid",
        "readahead",
        "setxattr",
        "lsetxattr",
        "fsetxattr",
        "getxattr",
        "lgetxattr",
        "fgetxattr",
        "listxattr",
        "llistxattr",
        "flistxattr",
        "removexattr",
        "lremovexattr",
        "fremovexattr",
        "tkill",
        "time",
        "futex",
        "sched_setaffinity",
        "sched_getaffinity",
        "set_thread_area",
        "io_setup",
        "io_destroy",
        "io_getevents",
        "io_submit",
        "io_cancel",
        "get_thread_area",
        "lookup_dcookie",
        "epoll_create",
        "epoll_ctl_old",
        "epoll_wait_old",
        "remap_file_pages",
        "getdents64",
        "set_tid_address",
        "restart_syscall",
        "semtimedop",
        "fadvise64",
        "timer_create",
        "timer_settime",
        "timer_gettime",
        "timer_getoverrun",
        "timer_delete",
        "clock_settime",
        "clock_gettime",
        "clock_getres",
        "clock_nanosleep",
        "exit_group",
        "epoll_wait",
        "epoll_ctl",
        "tgkill",
        "utimes",
        "vserver",
        "mbind",
        "set_mempolicy",
        "get_mempolicy",
        "mq_open",
        "mq_unlink",
        "mq_timedsend",
        "mq_timedreceive",
        "mq_notify",
        "mq_getsetattr",
        "kexec_load",
        "waitid",
        "add_key",
        "request_key",
        "keyctl",
        "ioprio_set",
        "ioprio_get",
        "inotify_init",
        "inotify_add_watch",
        "inotify_rm_watch",
        "migrate_pages",
        "openat",
        "mkdirat",
        "mknodat",
        "fchownat",
        "futimesat",
        "newfstatat",
        "unlinkat",
        "renameat",
        "linkat",
        "symlinkat",
        "readlinkat",
        "fchmodat",
        "faccessat",
        "pselect6",
        "ppoll",
        "unshare",
        "set_robust_list",
        "get_robust_list",
        "splice",
        "tee",
        "sync_file_range",
        "vmsplice",
        "move_pages",
        "utimensat",
        "epoll_pwait",
        "signalfd",
        "timerfd_create",
        "eventfd",
        "fallocate",
        "timerfd_settime",
        "timerfd_gettime",
        "accept4",
        "signalfd4",
        "eventfd2",
        "epoll_create1",
        "dup3",
        "pipe2",
        "inotify_init1",
        "preadv",
        "pwritev",
        "rt_tgsigqueueinfo",
        "perf_event_open",
        "recvmmsg",
        "fanotify_init",
        "fanotify_mark",
        "prlimit64",
        "name_to_handle_at",
        "open_by_handle_at",
        "clock_adjtime",
        "syncfs",
        "sendmmsg",
        "setns",
        "getcpu",
        "process_vm_readv",
        "process_vm_writev",
        "kcmp",
        "finit_module",
        "sched_setattr",
        "sched_getattr",
        "renameat2",
        "seccomp",
        "getrandom",
        "memfd_create",
        "kexec_file_load",
        "bpf",
        "execveat",
        "userfaultfd",
        "membarrier",
        "mlock2",
        "copy_file_range",
        "preadv2",
        "pwritev2",
        "pkey_mprotect",
        "pkey_alloc",
        "pkey_free"
    ];

    let argv: Vec<_> = std::env::args().collect();
    let mut cmd = Command::new(&argv[1]);
    for arg in &argv{
        cmd.arg(arg);
    }
    let option1 ="-v";
    let option2 ="-V";
    
    
    
    
    //println!("se utilizo la opcion: {}",option);
    //Hashmap to store the count call, can compare to strace for numbers!
    let mut map = HashMap::new();

    //allow the child to be traced
    let output = cmd.before_exec(traceme);

    let mut child = cmd.spawn().expect("child process failed");

    let pid = nix::unistd::Pid::from_raw(child.id() as libc::pid_t);

    //allow parent to be stopped everytime there is a SIGTRAP sent because a syscall happened.
    ptrace::setoptions(
        pid,
        Options::PTRACE_O_TRACESYSGOOD | Options::PTRACE_O_TRACEEXEC,
    )
    .unwrap();

    waitpid(pid, None);

    /// Whether we are exiting (rather than entering) a syscall.
    /// ptrace is stopped both times when exiting and entering a syscall, we only
    /// need to stop once.  
    let mut exit = true;
    if argv.iter().any(|i| i==option1) {
        println!("\n\n\nSE ESCOGIO LA OPCION -v\n\n\n");
        
       
        loop {
            //se obtienen los registros de donde se detuvo ptrace.
            let regs = match get_regs(pid) {
                Ok(x) => x,
                Err(err ) => {
                    eprintln!("End of ptrace {:?}", err);
                    break;
                }
            };

            //println!("{} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} ",elapsed.as_secs_f64(),regs.r15, regs.r14,regs.r13, regs.r12,regs.r11, regs.r10,regs.r9,regs.r8,regs.rbp,regs.rbx,regs.rax,regs.rcx,regs.rdx,regs.rsi,regs.rdi);

            if exit {
                //El numero de la llamada esta almacenado dentro de orig_rax_register.
                //Se traduce de numero al nombre del syscall usando un array que guarda las syscalls
                let mut syscallName = syscallNames[(regs.orig_rax) as usize];

                match map.get(&syscallName) {
                    
                    Some(&number) => map.insert(syscallName, number + 1),
                    _ => map.insert(syscallName, 1),//se agregan las syscalls al HashMap indexadas.
                };
            }

            unsafe {
                ptrace(//se hace el request de la llamada al sistema usando ptrace()
                    Request::PTRACE_SYSCALL,
                    pid,
                    ptr::null_mut(),
                    ptr::null_mut(),
                );
            }

            waitpid(pid, None);
            exit = !exit;
        }
    
    }
    if argv.iter().any(|i| i==option2) {//se busca en el vector si la opcion es -V
        println!("\n\nSE ESCOGIO LA OPCION -V\n\n");
        
       
        loop {
            //se obtienen los registros de donde se detuvo ptrace.
            let regs = match get_regs(pid) {
                Ok(x) => x,
                Err(err ) => {
                    eprintln!("End of ptrace {:?}", err);
                    break;
                }
            };
            //println!("{}{}");
            
            //pause();
            if exit {
                //El numero de la llamada esta almacenado dentro de orig_rax_register.
                //Se traduce de numero al nombre del syscall usando un array que guarda las syscalls
                let mut syscallName = syscallNames[(regs.orig_rax) as usize];

                match map.get(&syscallName) {
                    
                    Some(&number) => map.insert(syscallName, number + 1),
                    _ => map.insert(syscallName, 1),
                };
                
            }
            
            unsafe {
                ptrace(//se hace el request de la llamada al sistema usando ptrace()
                    Request::PTRACE_SYSCALL,
                    pid,
                    ptr::null_mut(),
                    ptr::null_mut(),
                );
            }

            waitpid(pid, None);
            exit = !exit;
        }
        
        
        }
    
    let mut counter : i32 = 0;

    for (syscall, &number) in map.iter() {
        
        print!(" Nombre de la llamada al sistema:  |{0}| \n Cantidad de veces que se llamó: {1}\n", syscall, number);
        println!("------------------------------------------");
        counter+=number;
    }
    println!("------------------------------------------\n");
    println!("Total  de llamadas al Sistema: {}\n", counter);   
    
}