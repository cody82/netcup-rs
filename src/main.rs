use clap::Parser;
use reqwest;
use serde::{Deserialize, Serialize};

use std::fs;
use std::process::exit;

const NETCUP_API_URL: &str = "https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON";

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginParam {
    pub customernumber: String,
    pub apikey: String,
    pub apipassword: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Login {
    pub action: String,
    pub param: LoginParam,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub login: LoginParam,
    pub enable_ipv4: bool,
    pub enable_ipv6: bool,
    pub domains: Vec<DomainConfig>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginResponseData {
    apisessionid: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginResponse {
    pub serverrequestid: String,
    pub clientrequestid: String,
    pub action: String,
    pub status: String,
    pub statuscode: u32,
    pub shortmessage: String,
    pub longmessage: String,
    pub responsedata: LoginResponseData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InfoDnsRecordsRequestParam {
    pub domainname: String,
    pub customernumber: String,
    pub apikey: String,
    pub apisessionid: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct InfoDnsRecordsRequest {
    pub action: String,
    pub param: InfoDnsRecordsRequestParam,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DnsRecord {
    pub hostname: String,
    #[serde(rename(deserialize = "type", serialize = "type"))]
    pub type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    pub destination: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleterecord: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InfoDnsRecordsResponseData {
    pub dnsrecords: Vec<DnsRecord>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InfoDnsRecordsResponse {
    pub responsedata: InfoDnsRecordsResponseData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateDnsRecordsRequestParam {
    pub domainname: String,
    pub customernumber: String,
    pub apikey: String,
    pub apisessionid: String,
    pub dnsrecordset: InfoDnsRecordsResponseData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateDnsRecordsRequest {
    pub action: String,
    pub param: UpdateDnsRecordsRequestParam,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DomainConfig {
    pub domain: String,
    pub subdomains: Vec<String>,
}

fn get(url: &str) -> String {
    reqwest::blocking::get(url)
        .expect("xxx")
        .text()
        .expect("msg")
}

fn post(url: &str, _request: &str) -> String {
    let client = reqwest::blocking::Client::new();
    client.post(url).send().expect("xxx").text().expect("msg")
}

fn login(data: &Login) -> LoginResponse {
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(NETCUP_API_URL)
        .json(data)
        .send()
        .expect("xxx")
        .text()
        .expect("msg");
    let deserialized: LoginResponse = serde_json::from_str(response.as_str()).unwrap();
    //println!("Login:\n{}", deserialized.longmessage);
    deserialized
}

fn infoDnsRecords(
    login: &Login,
    loginresponse: &LoginResponse,
    domain: &str,
) -> InfoDnsRecordsResponse {
    let client = reqwest::blocking::Client::new();
    let data = InfoDnsRecordsRequest {
        action: String::from("infoDnsRecords"),
        param: InfoDnsRecordsRequestParam {
            domainname: String::from(domain),
            customernumber: login.param.customernumber.clone(),
            apikey: login.param.apikey.clone(),
            apisessionid: loginresponse.responsedata.apisessionid.clone(),
        },
    };

    let response = client
        .post(NETCUP_API_URL)
        .json(&data)
        .send()
        .expect("xxx")
        .text()
        .expect("msg");
    //println!("{}", response);
    let deserialized: InfoDnsRecordsResponse = serde_json::from_str(response.as_str()).unwrap();
    //println!("infoDnsRecords:\n{:?}", deserialized);
    deserialized
}

fn updateDnsRecords(
    login: &Login,
    loginresponse: &LoginResponse,
    domain: &str,
    dnsrecords: &Vec<DnsRecord>,
) {
    let client = reqwest::blocking::Client::new();
    let data = UpdateDnsRecordsRequest {
        action: String::from("updateDnsRecords"),
        param: UpdateDnsRecordsRequestParam {
            domainname: String::from(domain),
            customernumber: login.param.customernumber.clone(),
            apikey: login.param.apikey.clone(),
            apisessionid: loginresponse.responsedata.apisessionid.clone(),
            dnsrecordset: InfoDnsRecordsResponseData {
                dnsrecords: dnsrecords.to_vec(),
            },
        },
    };
    //rintln!("{}", serde_json::to_string(&data).unwrap());
    let _response = client
        .post(NETCUP_API_URL)
        .json(&data)
        .send()
        .expect("xxx")
        .text()
        .expect("msg");
    //let deserialized: InfoDnsRecordsResponse = serde_json::from_str(response.as_str()).unwrap();
    //println!("updateDnsRecords:\n{:?}", response);
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to config file
    #[arg(short, long)]
    config: String,
}

fn main() {
    let args = Args::parse();

    let config: Option<Config> = match fs::read_to_string(args.config) {
        Ok(x) => Some(serde_json::from_str(x.as_str()).unwrap()),
        Err(_x) => None,
    };

    if config.is_none() {
        println!("no config");
        exit(1);
    }

    let cfg = config.unwrap();

    let enable_ipv4: bool = cfg.enable_ipv4;
    let enable_ipv6 = cfg.enable_ipv6;

    let logindata = Login {
        action: String::from("login"),
        param: cfg.login,
    };

    let login_response = login(&logindata);
    let ipv6 = get("https://v6.ident.me/");
    println!("IPv6: {}", ipv6);
    let ipv4 = get("https://v4.ident.me/");
    println!("IPv4: {}", ipv4);

    let domain_configs = &cfg.domains;

    for domain_config in domain_configs {
        let domain = &domain_config.domain;
        let hostnames = &domain_config.subdomains;
        let mut updates = Vec::<DnsRecord>::new();
        let records = infoDnsRecords(&logindata, &login_response, domain.as_str());

        // updates
        for record in &records.responsedata.dnsrecords {
            if hostnames.contains(&record.hostname) {
                if record.type_ == "A" && enable_ipv4 {
                    if record.destination != ipv4 {
                        println!("updating: {} {} {}", domain, record.hostname, record.type_);
                        let mut clone = record.clone();
                        clone.destination = ipv4.clone();
                        updates.push(clone)
                    }
                } else if record.type_ == "AAAA" && enable_ipv6 {
                    if record.destination != ipv6 {
                        println!("updating: {} {} {}", domain, record.hostname, record.type_);
                        let mut clone = record.clone();
                        clone.destination = ipv6.clone();
                        updates.push(clone)
                    }
                }
            }
        }
        //new entries
        for hostname in hostnames {
            let filtered_records: Vec<&DnsRecord> = records
                .responsedata
                .dnsrecords
                .iter()
                .filter(|x| &x.hostname == hostname)
                .collect();
            if filtered_records.len() == 0 {
                if enable_ipv4 {
                    println!("creating: {} {} {}", domain, hostname, "A");
                    updates.push(DnsRecord {
                        hostname: hostname.clone(),
                        type_: String::from("A"),
                        destination: ipv4.clone(),
                        priority: None,
                        deleterecord: None,
                        state: None,
                        id: None,
                    })
                }
                if enable_ipv6 {
                    println!("creating: {} {} {}", domain, hostname, "AAAA");
                    updates.push(DnsRecord {
                        hostname: hostname.clone(),
                        type_: String::from("AAAA"),
                        destination: ipv6.clone(),
                        priority: None,
                        deleterecord: None,
                        state: None,
                        id: None,
                    })
                }
            }
        }

        if updates.len() > 0 {
            //println!("{}:\n{:?}", domain, updates);
            updateDnsRecords(&logindata, &login_response, domain.as_str(), &updates);
        } else {
            println!("nothing to do!")
        }
    }
}
