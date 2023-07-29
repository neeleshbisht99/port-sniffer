/*
A port sniffer, also known as a port scanner, is a software tool used to discover and identify open ports on a computer or network device. Ports are communication endpoints that allow computers to send and receive data over a network. Each port is associated with a specific protocol or service.
Port sniffers work by sending network packets to various ports on a target system and analyzing the response to determine whether the port is open, closed, or filtered.
*/

use std::{env, io};
use std::io::Write;
use std::net::{IpAddr, TcpStream};
use std::str::FromStr;
use std::process;
use std::sync::mpsc::{Sender, channel};
use std::thread;


const MAX: u16 = 65535;

struct Arguments {
    flag: String,
    ipaddr: IpAddr,
    threads: u16,
}



/*
Let's break down the function's implementation step by step:
The function takes a slice of strings called args as input.
The function first checks the length of args to ensure it has the appropriate number of arguments (at least 2 and at most 4). If the length doesn't meet the required conditions, it returns an Err with an appropriate error message.
If the length of args is valid, the function proceeds with further checks. It clones the second element (args[1]) of args into the variable f. This element is expected to be an IP address or a flag.
It attempts to parse the IP address from the value stored in f using IpAddr::from_str(&f). If successful, it constructs an Arguments struct with an empty flag, the parsed IP address, and threads set to 4. The constructed Arguments instance is then returned within an Ok.
If parsing the IP address fails, the function assumes that f contains a flag and not an IP address. It checks if the flag indicates a help request (-h or -help) and handles different scenarios accordingly:
If the flag contains a help request and the number of arguments is exactly 2, it prints the usage message and returns an Err with the message "help" to indicate that the help message was shown.
If the flag contains a help request but the number of arguments is not 2, it returns an Err with the message "too many arguments" as there are too many arguments for a help request.
If the flag indicates a thread (-j), it parses the number of threads from args[2], and the IP address from args[3]. If parsing is successful, it constructs an Arguments instance with the parsed data and returns it within an Ok.
If the flag is not recognized, it returns an Err with the message "invalid syntax".
Overall, this code attempts to construct instances of the Arguments struct based on the provided input. It handles different cases depending on the input format and provides appropriate error messages when necessary.
*/

impl Arguments {
    fn new(args: &[String]) -> Result<Arguments, &'static str>{
        if args.len() < 2 {
            return Err("not enough arguments");
        } else if args.len() > 4 {
            return Err("too many arguments");
        }

        let f = args[1].clone();
        if let Ok(ipaddr) = IpAddr::from_str(&f){
            return Ok(Arguments {
                flag: String::from(""),
                ipaddr,
                threads: 4,
            });
        } else {
            let flag = args[1].clone();
            if flag.contains("-h") || flag.contains("-help") && args.len() == 2 {
                println!("Usage : -j to select how many threads you want
                \r\n -h or -help to show this help message");
                return Err("help");
            } else if flag.contains("-h") || flag.contains("-help"){
                return Err("too many arguments");
            } else if flag.contains("-j"){
                let ipaddr = match IpAddr::from_str(&args[3]) {
                    Ok(s) => s,
                    Err(_) => return Err("not a valid IPADDR; must be IPv4 or IPv6")
                };
                let threads = match args[2].parse::<u16>(){
                    Ok(s) => s,
                    Err(_) => return Err("failed to parse thread number")
                };
                return Ok(Arguments{threads, flag, ipaddr});
            } else {
                return Err("invalid syntax");
            }
        }
    }
}



/*
The function takes the following parameters:
tx: A Sender<u16> which is used to send the port numbers of successfully connected ports to another part of the program.
start_port: The starting port number from which the scanning will begin.
addr: The IpAddr representing the IP address to scan for open ports.
num_threads: The number of ports to scan at a time.
It initializes a mutable variable port with the value start_port + 1, indicating the first port to scan.
The function enters a loop that continues until the scanning is complete.
Within the loop, it tries to establish a TCP connection to the IP address and port using TcpStream::connect((addr, port)).
If the connection attempt is successful (no error occurs), it prints a dot (.) to indicate progress, flushes the output to the console, and then sends the port number through the tx channel using tx.send(port). The successful connection indicates that the port is open.
If the connection attempt fails (an error occurs), it simply proceeds to the next iteration of the loop without doing anything.
After attempting to connect to the current port, it checks whether there are at least num_threads number of ports left to scan. If the difference between the maximum port value (MAX) and the current port is less than or equal to num_threads, it means there are fewer ports remaining to scan than the number of threads allowed to scan at a time. In this case, the loop breaks to stop scanning further.
If there are more ports to scan, it increments the port by num_threads, effectively moving to the next set of ports to scan in the next iteration.
*/
fn scan(tx:Sender<u16>, start_port:u16, addr: IpAddr, num_threads: u16){
    let mut port: u16 = start_port + 1;
    loop {
        match TcpStream::connect((addr, port)){
            Ok(_) => {
                print!(".");
                io::stdout().flush().unwrap();
                tx.send(port).unwrap();
            }
            Err(_) => {}
        }
        if (MAX - port) <= num_threads {
            break;
        }
        port += num_threads;
    }
}


fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let arguments = Arguments::new(&args).unwrap_or_else(
        |err|{
            if err.contains("help") {
                process::exit(0);
            } else {
                eprintln!("{} problem parsing arguments: {}", program,err);
                process::exit(0);
            }
        }
    );
    let num_threads = arguments.threads;
    let addr = arguments.ipaddr;
    let (tx, rx) = channel();
    for i in 0..num_threads {
        let tx = tx.clone();
        let num_threads = num_threads.clone();
        scan(tx, i, addr, num_threads);
    }

    let mut out = vec![];
    drop(tx);
    for p in rx {
        out.push(p);
    }

    println!("");
    out.sort();
    for v in out {
        println!("{} is open", v);
    }
}


// ip_sniffer.exe -h
// ip_sniffer.exe -j 100 192.168.1.1
// ip_sniffer.exe 192.168.1.1