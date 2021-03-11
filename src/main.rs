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



fn pause() {//genera una pausa en la terminal donde se ejecuta el programa

    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    
    write!(stdout, "\n Presione la tecla \"Enter\" para continuar\n").unwrap();
    println!("-------------------------------------------");
    stdout.flush().unwrap();//se imprime manualmente para evitar el salto de linea
    //se lee lo ingresado 
    let _ = stdin.read(&mut [0u8]).unwrap();
}

fn main() {
    //se agregan todas las syscalls en un vector para luego poder desplegarlas segun sean utilizadas por el sistema.
    let syscallNames : Vec<&str > = vec!["read","write","open","close","stat","fstat","lstat","poll","lseek","mmap","mprotect","munmap","brk","rt_sigaction","rt_sigprocmask","rt_sigreturn","ioctl",
"pread64","pwrite64","readv","writev","access","pipe","select","sched_yield","mremap","msync","mincore","madvise","shmget","shmat","shmctl",
"dup","dup2","pause","nanosleep","getitimer","alarm","setitimer","getpid","sendfile","socket","connect","accept","sendto","recvfrom","sendmsg","recvmsg","shutdown",
"bind","listen","getsockname","getpeername","socketpair","setsockopt","getsockopt","clone","fork","vfork","execve","exit","wait4","kill","uname","semget",
"semop","semctl","shmdt","msgget","msgsnd","msgrcv","msgctl","fcntl","flock","fsync","fdatasync","truncate","ftruncate","getdents","getcwd","chdir",
"fchdir","rename","mkdir","rmdir","creat","link","unlink","symlink","readlink","chmod","fchmod","chown","fchown","lchown","umask","gettimeofday","getrlimit","getrusage","sysinfo",
"times","ptrace","getuid","syslog","getgid","setuid","setgid","geteuid","getegid","setpgid","getppid","getpgrp","setsid","setreuid","setregid","getgroups","setgroups",
"setresuid","getresuid","setresgid","getresgid","getpgid","setfsuid","setfsgid","getsid","capget","capset","rt_sigpending","rt_sigtimedwait","rt_sigqueueinfo","rt_sigsuspend",
"sigaltstack","utime","mknod","uselib","personality","ustat","statfs","fstatfs","sysfs","getpriority","setpriority","sched_setparam","sched_getparam","sched_setscheduler",
"sched_getscheduler","sched_get_priority_max","sched_get_priority_min","sched_rr_get_interval","mlock","munlock","mlockall","munlockall","vhangup","modify_ldt",
"pivot_root","_sysctl","prctl","arch_prctl","adjtimex","setrlimit","chroot","sync","acct","settimeofday","mount","umount2","swapon","swapoff","reboot",
"sethostname","setdomainname","iopl","ioperm","create_module","init_module","delete_module","get_kernel_syms","query_module","quotactl","nfsservctl","getpmsg","putpmsg",
"afs_syscall","tuxcall","security","gettid","readahead","setxattr","lsetxattr","fsetxattr","getxattr","lgetxattr","fgetxattr","listxattr","llistxattr","flistxattr",
"removexattr","lremovexattr","fremovexattr","tkill","time","futex","sched_setaffinity","sched_getaffinity","set_thread_area","io_setup","io_destroy","io_getevents",
"io_submit","io_cancel","get_thread_area","lookup_dcookie","epoll_create","epoll_ctl_old","epoll_wait_old","remap_file_pages","getdents64","set_tid_address",
"restart_syscall","semtimedop","fadvise64","timer_create","timer_settime","timer_gettime","timer_getoverrun","timer_delete","clock_settime","clock_gettime","clock_getres","clock_nanosleep",
"exit_group","epoll_wait","epoll_ctl","tgkill","utimes","vserver","mbind","set_mempolicy","get_mempolicy","mq_open","mq_unlink","mq_timedsend","mq_timedreceive","mq_notify",
"mq_getsetattr","kexec_load","waitid","add_key","request_key","keyctl","ioprio_set","ioprio_get","inotify_init","inotify_add_watch","inotify_rm_watch","migrate_pages",
"openat","mkdirat","mknodat","fchownat","futimesat","newfstatat","unlinkat","renameat","linkat","symlinkat","readlinkat","fchmodat","faccessat","pselect6",
"ppoll","unshare","set_robust_list","get_robust_list","splice","tee","sync_file_range","vmsplice","move_pages","utimensat","epoll_pwait","signalfd","timerfd_create","eventfd",
"fallocate","timerfd_settime","timerfd_gettime","accept4","signalfd4","eventfd2","epoll_create1","dup3","pipe2","inotify_init1","preadv","pwritev","rt_tgsigqueueinfo",
"perf_event_open","recvmmsg","fanotify_init","fanotify_mark","prlimit64","name_to_handle_at","open_by_handle_at","clock_adjtime","syncfs","sendmmsg","setns","getcpu",
"process_vm_readv","process_vm_writev","kcmp","finit_module","sched_setattr","sched_getattr","renameat2","seccomp","getrandom","memfd_create","kexec_file_load","bpf",
"execveat","userfaultfd","membarrier","mlock2","copy_file_range","preadv2","pwritev2","pkey_mprotect","pkey_alloc","pkey_free"
    ];
    //el siguiente Array sirve como complemento del vector anterior, donde cada valor, es la correspondiente descripcion de las llamadas al systema.
    pub static syscallDescriptions: [&str; 332] = ["read from a file descriptor","write to a file descriptor","open and possibly create a file","close a file descriptor","no posee mas informacion",
"no posee mas informacion","no posee mas informacion","wait for some event on a file descriptor","reposition read/write file offset","map or unmap files or devices into memory","set protection on a region of memory",
"map or unmap files or devices into memory","change data segment size","examine and change a signal action","examine and change blocked signals","no posee mas informacion","control device",
"read from or write to a file descriptor at a given offset","read from or write to a file descriptor at a given offset","read or write data into multiple buffers",
"read or write data into multiple buffers","check user's permissions for a file","create pipe","synchronous I/O multiplexing","yield the processor","remap a virtual memory address",
"synchronize a file with a memory map","determine whether pages are resident in memory","give advice about use of memory","allocates a System V shared memory segment","System V shared memory operations","System V shared memory control",
"duplicate a file descriptor","duplicate a file descriptor","wait for signal","high","get or set value of an interval timer","set an alarm clock for delivery of a signal",
"get or set value of an interval timer","get process identification","transfer data between file descriptors",
"create an endpoint for communication","initiate a connection on a socket","accept a connection on a socket","send a message on a socket","receive a message from a socket",
"send a message on a socket","receive a message from a socket","shut down part of a full","bind a name to a socket","listen for connections on a socket","get socket name",
"get name of connected peer socket","create a pair of connected sockets","get and set options on sockets","get and set options on sockets",
"no posee mas informacion","no posee mas informacion","no posee mas informacion","no posee mas informacion","terminate the calling process","wait for process to change state, BSD style","send signal to a process","no posee mas informacion","get a System V semaphore set identifier",
"System V semaphore operations","System V semaphore control operations","System V shared memory operations","get a System V message queue identifier","System V message queue operations",
"System V message queue operations","System V message control operations","manipulate file descriptor","apply or remove an advisory lock on an open file",
"synchronize a file's in","synchronize a file's in","truncate a file to a specified length","truncate a file to a specified length",
"get directory entries","get current working directory","change working directory",
"change working directory","change the name or location of a file",
"create a directory","delete a directory","open and possibly create a file","make a new name for a file","delete a name and possibly the file it refers to","make a new name for a file",
"read value of a symbolic link","change permissions of a file",
"change permissions of a file","change ownership of a file","change ownership of a file","change ownership of a file","set file mode creation mask","get / set time",
"get/set resource limits","get resource usage","return system information","get process times","process trace","get user identity","read and/or clear kernel message ring buffer; set console_loglevel",
"get group identity","set user identity","set group identity","get user identity","get group identity",
"set/get process group","get process identification","set/get process group","creates a session and sets the process group ID","set real and/or effective user or group ID",
"set real and/or effective user or group ID","get/set list of supplementary group IDs","get/set list of supplementary group IDs","set real, effective and saved user or group ID","get real, effective and saved user/group IDs",
"set real, effective and saved user or group ID","get real, effective and saved user/group IDs",
"set/get process group","set user identity used for filesystem checks","set group identity used for filesystem checks","get session ID",
"set/get capabilities of thread(s)","set/get capabilities of thread(s)","examine pending signals","synchronously wait for queued signals","queue a signal and data",
"wait for a signal","set and/or get signal stack context",
"change file last access and modification times","create a special or ordinary file","no posee mas informacion","set the process execution domain","get filesystem statistics",
"get filesystem statistics","get filesystem statistics","get filesystem type information","get/set program scheduling priority",
"get/set program scheduling priority","set and get scheduling parameters","set and get scheduling parameters","set and get scheduling policy/parameters","set and get scheduling policy/parameters",
"get static priority range","get static priority range","get the SCHED_RR interval for the named process","lock and unlock memory",
"lock and unlock memory","lock and unlock memory","lock and unlock memory","virtually hangup the current terminal","get or set a per","change the root filesystem","read/write system parameters","operations on a process","set architecture",
"tune kernel clock","get/set resource limits","change root directory","commit filesystem caches to disk","switch process accounting on or off","get / set time",
"mount filesystem","unmount filesystem","start/stop swapping to file/device","start/stop swapping to file/device","reboot or enable/disable Ctrl",
"get/set hostname","get/set NIS domain name","no posee mas informacion","set port input/output permissions","no posee mas informacion","load a kernel module","unload a kernel module",
"no posee mas informacion","no posee mas informacion","manipulate disk quotas","no posee mas informacion","no posee mas informacion","no posee mas informacion","no posee mas informacion","no posee mas informacion","no posee mas informacion","get thread identification","initiate file readahead into page cache",
"set an extended attribute value","set an extended attribute value","set an extended attribute value","retrieve an extended attribute value","retrieve an extended attribute value","retrieve an extended attribute value",
"list extended attribute names","list extended attribute names","list extended attribute names","remove an extended attribute","remove an extended attribute",
"remove an extended attribute","send a signal to a thread","get time in seconds","fast user","set and get a thread's CPU affinity mask","set and get a thread's CPU affinity mask","no posee mas informacion",
"create an asynchronous I/O context","destroy an asynchronous I/O context","read asynchronous I/O events from the completion queue","submit asynchronous I/O blocks for processing",
"cancel an outstanding asynchronous I/O operation","no posee mas informacion","return a directory entry's path","open an epoll file descriptor",
"no posee mas informacion","no posee mas informacion","create a nonlinear file mapping","get directory entries","set pointer to thread ID","restart a system call after interruption by a stop signal","System V semaphore operations",
"predeclare an access pattern for file data","create a POSIX per","arm/disarm and fetch state of POSIX per","arm/disarm and fetch state of POSIX per","get overrun count for a POSIX per",
"delete a POSIX per","clock and time functions","clock and time functions","clock and time functions","high","exit all threads in a process","wait for an I/O event on an epoll file descriptor","control interface for an epoll file descriptor",
"send a signal to a thread","change file last access and modification times",
"no posee mas informacion","set memory policy for a memory range","set default NUMA memory policy for a thread and its children","retrieve NUMA memory policy for a thread",
"open a message queue","remove a message queue","send a message to a message queue","receive a message from a message queue","register for notification when a message is available",
"get/set message queue attributes","load a new kernel for later execution","wait for process to change state","add a key to the kernel's key management facility","request a key from the kernel's key management facility",
"manipulate the kernel's key management facility","get/set I/O scheduling class and priority","get/set I/O scheduling class and priority","initialize an inotify instance",
"add a watch to an initialized inotify instance","remove an existing watch from an inotify instance","move all pages in a process to another set of nodes","open and possibly create a file",
"create a directory","create a special or ordinary file","change ownership of a file","change timestamps of a file relative to a directory file descriptor","get file status",
"delete a name and possibly the file it refers to","change the name or location of a file","make a new name for a file","make a new name for a file","read value of a symbolic link",
"change permissions of a file","check user's permissions for a file","synchronous I/O multiplexing","wait for some event on a file descriptor","disassociate parts of the process execution context",
"get/set list of robust futexes","get/set list of robust futexes","splice data to/from a pipe","duplicating pipe content","sync a file segment with disk",
"splice user pages into a pipe","move individual pages of a process to another node","change file timestamps with nanosecond precision","wait for an I/O event on an epoll file descriptor","create a file descriptor for accepting signals",
"timers that notify via file descriptors","create a file descriptor for event notification","manipulate file space","timers that notify via file descriptors",
"timers that notify via file descriptors","accept a connection on a socket","create a file descriptor for accepting signals","create a file descriptor for event notification","open an epoll file descriptor",
"duplicate a file descriptor","create pipe","initialize an inotify instance","read or write data into multiple buffers","read or write data into multiple buffers","queue a signal and data","set up performance monitoring",
"receive multiple messages on a socket","create and initialize fanotify group","add, remove, or modify an fanotify mark on a filesystem object","get/set resource limits",
"obtain handle for a pathname and open file via a handle","obtain handle for a pathname and open file via a handle","no posee mas informacion",
"commit filesystem caches to disk","send multiple messages on a socket","reassociate thread with a namespace","determine CPU and NUMA node on which the calling thread is running","transfer data between process address spaces","transfer data between process address spaces",
"compare two processes to determine if they share a kernel resource","load a kernel module","set and get scheduling policy and attributes",
"set and get scheduling policy and attributes","change the name or location of a file","operate on Secure Computing state of the process","obtain a series of random bytes","create an anonymous file","load a new kernel for later execution",
"perform a command on an extended BPF map or program","no posee mas informacion","create a file descriptor for handling page faults in user space",
"issue memory barriers on a set of threads","lock and unlock memory","Copy a range of data from one file to another","read or write data into multiple buffers","read or write data into multiple buffers",
"set protection on a region of memory","allocate or free a protection key",
"allocate or free a protection key"
];

    let argv: Vec<_> = std::env::args().collect();
    let mut cmd = Command::new(&argv[1]);
    let option1 ="-v";
    let option2 ="-V";
    let mut flag1 = 0;//valida si se encontro un -v
    let mut flag2 = 0;//valida si se encontro un -V
    let mut flag0 = 0;//valida si ya se encontro el "programa"

    for argument in &argv[1..]{// se crea un for para recorrer todos lo argumentos que se toman de la linea de comandos del terminal
        if argument.as_str() != option1 &&  argument.as_str() != option2 && flag0 == 0//se toma el comando si no vienen opciones
        {
            
            cmd = Command::new(&argument);
            println!("programa: {}", &argument.as_str());
            flag0 = 1;
        }
        else if argument.as_str() == option1{//si viene la opcion -v se toma y se enciende la bandera para que no se considere mas
            flag1 = 1;
            println!("opcion = -v");
        }
        else if argument.as_str() == option2{//si viene la opcion -V se toma y se enciende la bandera para que no se considere mas
            flag2 = 1;
            println!("opcion = -V");
        }
        else{//una ves que se toman las opciones y el comando, solo sobran los parametros a ingresarle al comando
            cmd.arg(argument);
            println!("parametro del programa: {}", &argument.as_str())
        }


    }
    //Hashmap para almacenar la cantidad de llamadas al sistema
    let mut map = HashMap::new();

    //le permite al "child" ser monitoreado
    let output = cmd.before_exec(traceme);

    let mut child = cmd.spawn().expect("child process failed");

    let pid = nix::unistd::Pid::from_raw(child.id() as libc::pid_t);

    //Le permite al padre detenerse cada vez que hay un SIGTRAP enviado porque un Syscall sucedio
    ptrace::setoptions(
        pid,
        Options::PTRACE_O_TRACESYSGOOD | Options::PTRACE_O_TRACEEXEC,
    )
    .unwrap();

    waitpid(pid, None);
    

    let mut exit = true;


    if flag1==1 {
        println!("\n\nSE ESCOGIO LA OPCION -v\n\n");
    }
    else if flag2 ==1  {//se busca en el vector si la opcion es -V
        println!("\n\nSE ESCOGIO LA OPCION -V\n\n");
    }
       
    loop {
        //se obtienen los registros de donde se detuvo ptrace.
        let regs = match get_regs(pid) {
            Ok(x) => x,
            Err(err ) => {
                eprintln!("End of ptrace {:?}", err);
                break;
            }
        };
        
        

        if exit {
            //El numero de la llamada esta almacenado dentro de orig_rax_register.
            //Se traduce de numero al nombre del syscall usando un array que guarda las syscalls
            
            let  syscallName = syscallNames[(regs.orig_rax) as usize];
            let  syscallDescription = syscallDescriptions[(regs.orig_rax) as usize];
            if flag1==1 {//se busca en el vector si la opcion es -v
                println!("-Nombre de la llamada: {}\n   -Descripción de la llamada: {}" ,&syscallName,syscallDescription );
                println!("-------------------------------------------");
            
            }
            else if flag2 ==1  {//se busca en el vector si la opcion es -V
                println!("-Nombre de la llamada: {}\n   -Descripción de la llamada: {}" ,&syscallName,syscallDescription );
                println!("-------------------------------------------");
                pause();//se hacen las pausas para cada syscall que exista
            }
            
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
    
    
    
    
    let mut counter : i32 = 0;//contador general para saber cuantas llamadas al sistema se hicieron en total.

    for (syscall, &number) in map.iter() {
        
        print!(" Nombre de la llamada al sistema:  |{0}| \n Cantidad de veces que se llamó: {1}\n", syscall, number);
        println!("------------------------------------------");
        counter+=number;
    }
    println!("------------------------------------------\n");
    println!("Total  de llamadas al Sistema: {}\n", counter);   
    
}