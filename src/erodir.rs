extern crate reqwest;
extern crate clap;
extern crate erodirlib;
extern crate serde_derive;

use reqwest::{Url, UrlError, Client, RedirectPolicy, Proxy, header::{self,HeaderMap,HeaderValue}};
use erodirlib::{TargetBustInfo,HttpClientInfo,ThreadBuildHandle};
use clap::{App, Arg};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::fs::{File,OpenOptions};
use std::io::{stdout,Write,BufRead,BufReader};
use std::time::{Duration,Instant};
use std::process;

const VERSION: &str = "1.5";

fn main() {

    let args = App::new("-=[- EroDir")
        .version(format!("{} ---------------------------------------------]=-",VERSION).as_str())
        .author("-=[- @Pink_P4nther <pinkp4nther@protonmail.com> -------------]=-")
        .about("-=[- A web directory/file enumeration tool ------------------]=-")
        .arg(Arg::with_name("url")
            .short("u")
            .long("url")
            .value_name("http(s)://example.com:80/")
            .help("Target URL to bruteforce")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("entrylist")
            .short("e")
            .long("entrylist")
            .value_name("entries.lst")
            .help("File of entries for bruteforcing")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("extensionlist")
            .short("-x")
            .long("extlist")
            .value_name("extensions.lst")
            .help("File of extensions")
            .takes_value(true))
        .arg(Arg::with_name("threads")
            .short("t")
            .long("threads")
            .value_name("15")
            .help("Amount of threads to use (Default: 15)")
            .takes_value(true))
        .arg(Arg::with_name("proxy")
            .short("p")
            .long("proxy")
            .value_name("http(s)://proxy:port")
            .help("HTTP proxy to run traffic through")
            .takes_value(true))
        .arg(Arg::with_name("useragent")
            .short("U")
            .long("useragent")
            .value_name(format!("EroDir/{}",VERSION).as_str())
            .help("Change the default user agent")
            .takes_value(true))
        .arg(Arg::with_name("vhost")
            .short("v")
            .long("vhost")
            .value_name("v.host.com")
            .help("Change the host header")
            .takes_value(true))
        .arg(Arg::with_name("max-retries")
            .short("r")
            .long("max-retries")
            .value_name("3")
            .help("Tune the maximum retries per request (Default: 3)")
            .takes_value(true))
        .arg(Arg::with_name("invalid-cert")
            .short("-i")
            .long("invalid-cert")
            .help("Allows self-signed certificates from sites")
            .takes_value(false))
        .arg(Arg::with_name("cookie")
            .short("c")
            .long("cookie")
            .value_name("cookie=value")
            .help("Set cookie value")
            .takes_value(true))
        .arg(Arg::with_name("filter-codes")
            .short("f")
            .long("filter-codes")
            .value_name("200,302,301")
            .help("Shows specified HTTP codes (Default: 200,301,302,401,403)")
            .takes_value(true))
        .arg(Arg::with_name("timeout")
            .short("T")
            .long("timeout")
            .value_name("5")
            .help("Set the HTTP request timeout in seconds (Default: 5)")
            .takes_value(true))
        .arg(Arg::with_name("output")
            .short("o")
            .long("output")
            .value_name("outfile")
            .help("Output results to file")
            .takes_value(true))
        .arg(Arg::with_name("dirmode")
            .short("d")
            .long("dirmode")
            .help("Enables directory mode (Attempts a request with a an appended '/' instead of a blank)")
            .takes_value(false))
        .get_matches();

    let mut url = match args.value_of("url") {
        Some(url) => String::from(url),
        _ => String::from("")
        };
    
    // Check URL is good
    match Url::parse(url.as_str()) {
        Ok(_) => {},
        Err(pe) => {
            match pe {
                UrlError::EmptyHost => {println!("[!] --url can't have empty host!");process::exit(1)},
                UrlError::RelativeUrlWithoutBase => {println!("[!] --url value needs a base!");process::exit(1)},
                UrlError::IdnaError => {println!("[!] --url invalid international domain name!");process::exit(1)},
                UrlError::InvalidPort => {println!("[!] --url invalid port!");process::exit(1)},
                UrlError::InvalidIpv4Address => {println!("[!] --url invalid IPv4 address!");process::exit(1)},
                UrlError::InvalidIpv6Address => {println!("[!] --url invalid IPv6 address!");process::exit(1)},
                UrlError::InvalidDomainCharacter => {println!("[!] --url invalid domain character!");process::exit(1)},
                UrlError::RelativeUrlWithCannotBeABaseBase => {println!("[!] --url bad URL base!");process::exit(1)},
                UrlError::SetHostOnCannotBeABaseUrl => {println!("[!] --url bad URL base doesn't have a host!");process::exit(1)},
                UrlError::Overflow => {println!("[!] --url aw fuzzing my tool are we? URL can't be over 4GB long!");process::exit(1)}
            }
        }
    }

    let efile = match args.value_of("entrylist") {
        Some(entry) => String::from(entry),
        _ => String::from("")
    };

    let threads = match args.value_of("threads") {
        Some(t) => match String::from(t).parse::<u32>() {
            Ok(i) => {
                if i >= 1 {
                        i
                    } else {
                        println!("[!] --threads must have more than 0 threads!");
                        return;
                    }},
            Err(_) => {
                println!("[!] --threads must be a number!"); return;
            }
        },
        None => 15
    };

    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    println!("+-=[ EroDir v{} ]=-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+",VERSION);
    println!("+-=[ @Pink_P4nther ]=-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    if !url.ends_with("/") {url.push_str("/");}
    println!("[+] Target: \t\t[{}]",url);
    println!("[+] Entry List: \t[{}]",efile);

    if args.is_present("extensionlist") {
        println!("[+] Extension List: \t[{}]", match args.value_of("extensionlist") {
            Some(xe) => xe,
            None => "None"
        });
    }

    // Create TargetBustInfo object
    let mut erodir_obj = TargetBustInfo::new();
    erodir_obj.set_url(&url);
    erodir_obj.set_thread_count(threads);
    if args.is_present("max-retries") {
        println!("[+] Max Retries: \t[{}]", match args.value_of("max-retries") {
            Some(mr) => {
                erodir_obj.max_retries = match mr.parse::<u32>() {
                    Ok(i) => i,
                    Err(_) => {println!("[!] --max-retries must be a number!");process::exit(1);}
                }; // End of match that sets max_retries

                match mr.parse::<u32>() {
                    Ok(i) => i,
                    Err(_) => {println!("[!] --max-retries must be a number!");process::exit(1);}
                }// End of match that returns u32 to println!
            },
            None => 3
        }); // End of println! and match args.value_of
    }

    // Create HTTP Info object
    let mut http_cli_obj = HttpClientInfo::new();
    http_cli_obj.set_crp(RedirectPolicy::none());
    
    // Check if proxy enabled
    if args.is_present("proxy") {
        println!("[+] Proxy: \t[{}]", match args.value_of("proxy") {
            Some(p) => {
                http_cli_obj.set_proxy_flag(true);
                http_cli_obj.set_web_proxy(match Proxy::all(p) {
                    Ok(t) => t,
                    Err(t) => {println!("[!] Could not set web proxy: [{}]",t);process::exit(1);}
                });
                p},
            None => "None"
        });
    }

    if args.is_present("dirmode") {
        println!("[+] DirMode: \t\t[Active]");
        erodir_obj.dir_mode = true;
    }

    if args.is_present("timeout") {
        println!("[+] Timeout: \t\t[{}]", match args.value_of("timeout") {
            Some(to) => {
                http_cli_obj.timeout = match to.parse::<u64>() {
                    Ok(i) => i,
                    Err(_) => {println!("[!] --timeout must be a number!");process::exit(1);}
                }; // End of set timeout 

                match to.parse::<u64>() {
                    Ok(i) => i,
                    Err(_) => {println!("[!] --timeout must be a number!");process::exit(1)}
                } // End of return timeout as u64 to println
            },
            None => 5
        }); // End of value of match
    } else {
        println!("[+] Timeout: \t\t[5]");
        http_cli_obj.timeout = 5;
    }

    // Set default headers for http request
    let mut headers = HeaderMap::new();

    if args.is_present("useragent") {
        println!("[+] User-Agent: \t[{}]", match args.value_of("useragent") {
            Some(ua) => {
                headers.insert(header::USER_AGENT,HeaderValue::from_str(ua).unwrap());
            ua},
            None => "None"
        });
    } else {
        headers.insert(header::USER_AGENT,HeaderValue::from_str(format!("EroDir/{}",VERSION).as_str()).unwrap());
    }

    if args.is_present("vhost") {
        println!("[+] Virtual Host: \t[{}]", match args.value_of("vhost") {
            Some(vh) => {
                headers.insert(header::HOST, HeaderValue::from_str(vh).unwrap());
            vh},
            None => "None"
        });
    }

    if args.is_present("invalid-cert") {
        println!("[+] Invalid Certs: \t[Allow]");
        http_cli_obj.invalid_certs = true;
    }

    if args.is_present("cookie") {
        println!("[+] Cookie: \t\t[{}]", match args.value_of("cookie") {
            Some(cv) => {
                headers.insert(header::COOKIE, HeaderValue::from_str(cv).unwrap());
            cv},
            None => "None"
        });
    }

    if args.is_present("filter-codes") {
        println!("[+] HTTP codes: \t[{}]", match args.value_of("filter-codes") {
            Some(fc) => {
                for sfc in fc.split(",") {
                    http_cli_obj.filter_codes.push(sfc.parse::<u16>().unwrap());
                }
            fc},
            None => "None"
        });
    } else {
        println!("[+] HTTP codes: \t[200,301,302,401,403]");
        http_cli_obj.filter_codes = vec![200,301,302,401,403];
    }

    if args.is_present("output") {
        println!("[+] OutFile: \t\t[{}]", match args.value_of("output") {
            Some(of) => {
                erodir_obj.wfile_name = of.to_string();
                erodir_obj.wf_flag = true;
                of},
            None => "None"
        });
    }

    http_cli_obj.web_headers = headers;

    println!("[+] Threads: \t\t[{}]",threads);
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");

    // Get lines of entry list file and put into vector
    println!("[*] Reading lines..");
    let entrylines: Vec<String> = read_lines(&read_file(&efile));
    erodir_obj.set_entryl(&entrylines);


    // Build HTTP client
    http_cli_obj.web_client = build_http_client(&http_cli_obj);

    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        stat_verb(rx);
        process::exit(1);
    });

    // Check if there is extension list
    if args.is_present("extensionlist") {
        let xfile = match args.value_of("extensionlist") {
            Some(xe) => String::from(xe),
            _ => String::from("")
        };
        erodir_obj.set_extension_lines(&read_lines(&read_file(&xfile)));
        erodir_obj.set_ext_flag(true);
        println!("[*] Bruteforcing {} entries!",(entrylines.len() * erodir_obj.extension_lines.len()) + entrylines.len());
        thread_gen(&http_cli_obj, threads,&Arc::new(Mutex::new(erodir_obj)),tx);
    } else {
        println!("[*] Bruteforcing {} entries!",entrylines.len());
        thread_gen(&http_cli_obj, threads,&Arc::new(Mutex::new(erodir_obj)),tx);
    }

    println!("[+] Finished!");
}// End of main

fn stat_verb(rx: mpsc::Receiver<u16>) {

    let mut p_flag: u32 = 0;
    let syms = vec!["-","\\","|","/"];
    let mut i: usize = 3;

    loop {
        match rx.recv() {
            Ok(_) => {
            if p_flag == 100 {
                print!(" [{}]\r",syms[i]);
                match stdout().flush() {
                    Ok(_) => {},
                    Err(_) => {return;}
                }
                if i == 3 {i = 0;} else {
                    i = i + 1;}
                p_flag = 1;
            } else {
                p_flag = p_flag + 1;
            }},
            Err(_) => {return;}
        }
    }
}// End of stat_verb

fn build_http_client(hci: &HttpClientInfo) -> Client {
    if hci.proxy_flag {
        match Client::builder()
            .redirect(RedirectPolicy::none())
            .danger_accept_invalid_certs(hci.invalid_certs)
            .proxy(hci.web_proxy.clone())
            .default_headers(hci.web_headers.clone())
            .timeout(Duration::from_secs(hci.timeout))
            .build() {
                Ok(hc) => hc,
                Err(_) => {println!("[!] Could not create http client!");process::exit(1);}
            }
    } else if !hci.proxy_flag {
        match Client::builder()
            .redirect(RedirectPolicy::none())
            .danger_accept_invalid_certs(hci.invalid_certs)
            .default_headers(hci.web_headers.clone())
            .timeout(Duration::from_secs(hci.timeout))
            .build() {
                Ok(hc) => hc,
                Err(_) => {println!("[!] Could not create http client!");process::exit(1);}
            }
    } else {
        println!("[!] Failed to parse options for http client creation!");
        process::exit(1);
    }
}// End of build_http_client

fn read_file(file_name: &String) -> File {
    match File::open(file_name) {
        Ok(f) => f,
        Err(_) => {
            println!("[!] Could not open file: {}",file_name);
            process::exit(1);
        }
    }
}// End of read_file

fn read_lines(f: &File) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    let mut c: u32 = 1;
    for line in BufReader::new(f).lines() {
        v.insert(0, match line {
            Ok(l) => l,
            Err(e) => {
                /*
                println!("ERROR: {}",e,);*/
                println!("[!] Failed to read line {} of file! Reason: [{}]",c,e);
                continue;
            }
        });
        c = c + 1;
    }
    v
}// End of read_lines

fn thread_gen(hci: &HttpClientInfo, thread_count: u32,erodir_obj: &Arc<Mutex<TargetBustInfo>>, tx: mpsc::Sender<u16>) {
    // Set handle vector and start timer
    let mut build_handles: Vec<ThreadBuildHandle> = Vec::new();
    let mut t_handles: Vec<thread::JoinHandle<()>> = Vec::new();

    // Initialize threads
    for _ in 0..thread_count {


        let mut bh = ThreadBuildHandle::new();
        // Clone Http Client from HttpClientInfo
        bh.cloned_http_cli = hci.web_client.clone();

        // Clone Arc pointer
        bh.robj = erodir_obj.clone();

        // Clone filtered HTTP codes vector
        bh.fhc = hci.filter_codes.clone();

        // Clone other values that I don't want to clone during thread
        // None yet
        
        build_handles.push(bh);
        
    }

    println!("[*] Threads Built: {}",build_handles.len());
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");

    let now = Instant::now();

    //Spawn threads
    for th in build_handles {
        let tx = mpsc::Sender::clone(&tx);

        t_handles.push(thread::spawn(move || {
            request_engine(&th.robj, &th.cloned_http_cli, &th.fhc, tx);
        }));
    }

    for th in t_handles {
        th.join().unwrap();
    }

    let elapsed_time: u64 = now.elapsed().as_secs();
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    println!("[+] Time elapsed: {} Seconds.",elapsed_time);

    
    let h = erodir_obj.lock().unwrap();
    if h.wf_flag {
        let mut file = match OpenOptions::new()
            .append(true)
            .create(true)
            .open(&h.wfile_name) {
                Ok(f) => f,
                Err(e) => {
                    println!("[!] Could not create file: {}",e);
                    process::exit(1);
                }
            };
    
        for l in &h.wlines {
            if let Err(e) = writeln!(file,"{}",l) {
                eprintln!("Couldn't write to file: {}",e);
            }
        }
        println!("[+] Wrote output file!");
    }
}// End of thread_gen

fn request_engine(robj: &Arc<Mutex<TargetBustInfo>>, http_cli: &Client, fhc: &Vec<u16>, tx: mpsc::Sender<u16>) {
    let mut lines: Vec<String> = Vec::new();
    let tmpl = robj.lock().unwrap();
    let wf_f = tmpl.wf_flag;
    let dirmode_f = tmpl.dir_mode;
    drop(tmpl);
    
    loop {
        // Get Mutex handle
        let mut entry = robj.lock().unwrap();

        // Check that there are still entries left
        if entry.entry_lines.len() == 0 {
            drop(entry);
            break;
        }

        // Get next entry 
        let e = match entry.entry_lines.pop() {
            Some(e) => {
                if e == "" {continue;} else {e}
                },
            None => continue
        };

        let mut full_url = entry.url.clone();
        full_url.push_str(e.as_str());

        let mr = entry.max_retries;

        if entry.ext_flag {
            let ex = entry.extension_lines.clone();
            drop(entry);
            if dirmode_f {
                let mut durl = full_url.clone();
                durl.push_str("/");
                make_req(&durl, &http_cli, mr, &fhc, &mut lines, &wf_f);
                tx.send(1).unwrap();
            } else {
                make_req(&full_url, &http_cli, mr, &fhc, &mut lines, &wf_f);
                tx.send(1).unwrap();

            }

            for ext in ex.iter() {
                if ext == "" {continue;} else {
                    let mut full_ext_url = full_url.clone();
                    full_ext_url.push_str(ext.as_str());
                    make_req(&full_ext_url, &http_cli, mr, &fhc, &mut lines, &wf_f);
                    tx.send(1).unwrap();
                }
            }
        } else {
            drop(entry);
            if dirmode_f {
                let mut durl = full_url.clone();
                durl.push_str("/");
                make_req(&durl, &http_cli, mr, &fhc, &mut lines, &wf_f);
                tx.send(1).unwrap();
            } else {
                make_req(&full_url, &http_cli, mr, &fhc, &mut lines, &wf_f);
                tx.send(1).unwrap();
            }
        }
    }

    let mut tbi_handle = robj.lock().unwrap();
    for l in lines {
        tbi_handle.wlines.push(l);
    }
}// End of request_engine

fn make_req(url: &String, http_cli: &Client, mr: u32, fhc: &Vec<u16>, lines: &mut Vec<String>, wff: &bool) {

    let mut retry_counter = 0;

    loop {
        match http_cli.get(url.as_str()).send() {
            Ok(r) => {
                if fhc.contains(&r.status().as_u16()) {
                    println!("  => {} (Status: {})",url,r.status().as_str());
                    if *wff {
                        lines.push(format!("[{}] [{}]",r.status().as_str(),url));
                    }
                }
                break;
            },
            Err(e) => {
                if retry_counter < mr {
                    retry_counter = retry_counter + 1;
                } else {
                    req_error(e);
                    break;
                }
            }
        };
    }
}// End of make_req

fn req_error(e: reqwest::Error) {

    if e.is_http() {
        match e.url() {
            Some(url) => {
                println!("[!] Could not make request to: {}",url);
                match e.get_ref() {
                    None => {},
                    Some(err) => println!("[!] ERROR: {}",err)
                }
                process::exit(1);
            },
            None => println!("No URL specified"),
        }

    } else if e.is_server_error() {
        match e.url() {
            Some(url) => println!("[!] Server error at {}",url),
            None => {},
        }
    } else if e.is_client_error() {
        match e.url() {
            Some(url) => println!("[!] Client error at {}",url),
            None => {},
        }
    } else {
        println!("[!] Reached Timeout! Is server down?");
        process::exit(1);
    }
}// End of req_error