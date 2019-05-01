extern crate reqwest;
use reqwest::{Client, RedirectPolicy, Proxy, header::{HeaderMap}};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct TargetBustInfo {
    pub url: String,
    pub thread_count: u32,
    pub entry_lines: Vec<String>,
    pub extension_lines: Vec<String>,
    pub ext_flag: bool,
    pub max_retries: u32,
    pub wlines: Vec<String>,
    pub wfile_name: String,
    pub wf_flag: i8,
    pub dir_mode: bool,
}

impl TargetBustInfo {
    pub fn new() -> TargetBustInfo {
        TargetBustInfo {
            url: String::new(),
            thread_count: 0,
            entry_lines: Vec::new(),
            extension_lines: Vec::new(),
            ext_flag: false,
            max_retries: 3,
            wlines: Vec::new(),
            wfile_name: String::new(),
            wf_flag: 0,
            dir_mode: false,
        }
    }

    pub fn set_url(&mut self, url: &String) {
        self.url = url.clone();
    }

    pub fn set_thread_count(&mut self, tc: u32) {
        self.thread_count = tc;
    }

    pub fn set_entryl(&mut self, el: &Vec<String>) {
        self.entry_lines = el.clone();
    }

    pub fn set_extension_lines(&mut self, exl: &Vec<String>) {
        self.extension_lines = exl.clone();
    }

    pub fn set_ext_flag(&mut self, flag: bool) {
        self.ext_flag = flag;
    }
}

#[derive(Debug)]
pub struct HttpClientInfo {
    pub web_client: Client,
    pub custom_redirect_policy: RedirectPolicy,
    pub web_proxy: Proxy,
    pub proxy_flag: bool,
    pub web_headers: HeaderMap,
    pub invalid_certs: bool,
    pub cookie_flag: bool,
    pub filter_codes: Vec<u16>,
    pub timeout: u64,
}

impl HttpClientInfo {
    
    pub fn new() -> HttpClientInfo {
        HttpClientInfo {
            web_client: Client::new(),
            custom_redirect_policy: RedirectPolicy::none(),
            web_proxy: Proxy::all("http://none").unwrap(),
            proxy_flag: false,
            web_headers: HeaderMap::new(),
            invalid_certs: false,
            cookie_flag: false,
            filter_codes: Vec::new(),
            timeout: 5,
        }
    }

    pub fn set_crp(&mut self, crp: RedirectPolicy) {
        self.custom_redirect_policy = crp;
    }

    pub fn set_web_proxy(&mut self, wp: Proxy) {
        self.web_proxy = wp;
    }

    pub fn set_proxy_flag(&mut self, pf: bool) {
        self.proxy_flag = pf;
    }

}

pub struct ThreadBuildHandle {
    pub cloned_http_cli: Client,
    pub robj: Arc<Mutex<TargetBustInfo>>,
    pub fhc: Vec<u16>,
}

impl ThreadBuildHandle {
    pub fn new() -> ThreadBuildHandle {
        ThreadBuildHandle {
            cloned_http_cli: Client::new(),
            robj: Arc::new(Mutex::new(TargetBustInfo::new())),
            fhc: Vec::new(),
        }
    }
}