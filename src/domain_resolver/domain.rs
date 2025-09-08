use reqwest::{Client, Error};

use serde::Deserialize;
use std::collections::HashSet;
use std::iter::RepeatWith;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use trust_dns_resolver::config::*;
use trust_dns_resolver::{AsyncResolver, TokioAsyncResolver};

#[derive(Deserialize)]
struct QueryEntry {
    name_value: String,
}

#[derive(Debug)]
pub struct DomainError {
    pub message: String,
}

impl std::fmt::Display for DomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<String> for DomainError {
    fn from(msg: String) -> Self {
        DomainError { message: msg }
    }
}

impl From<reqwest::Error> for DomainError {
    fn from(err: reqwest::Error) -> Self {
        DomainError {
            message: format!("HTTP ERROR: {}", err),
        }
    }
}

impl From<trust_dns_resolver::error::ResolveError> for DomainError {
    fn from(err: trust_dns_resolver::error::ResolveError) -> Self {
        DomainError {
            message: format!("DNS Error: {}", err),
        }
    }
}

impl From<&str> for DomainError {
    fn from(msg: &str) -> Self {
        DomainError {
            message: msg.to_string(),
        }
    }
}

pub struct Domain {
    name: String,
    subdomains: Vec<Subdomain>,
    associated_ips: Vec<IpAddr>,
}

pub struct Subdomain {
    name: String,
    main_domain: String,
    associated_ip: IpAddr,
}

impl Domain {
    fn new(name: String) -> Self {
        Self {
            name: name,
            subdomains: Vec::new(),
            associated_ips: Vec::new(),
        }
    }
    fn add_subdomain(&mut self, subdomain: Subdomain) -> bool {
        if self.subdomains.iter().any(|s| s.name == subdomain.name) {
            return false;
        }

        self.subdomains.push(subdomain);
        true
    }

    fn remove_subdomain(&mut self, name: &str) -> Option<Subdomain> {
        if let Some(pos) = self.subdomains.iter().position(|s| s.name == name) {
            Some(self.subdomains.remove(pos))
        } else {
            None
        }
    }

    fn get_subdomains(&self) -> &Vec<Subdomain> {
        &self.subdomains
    }

    fn get_subdomain_count(&self) -> usize {
        self.subdomains.len()
    }

    fn print_subdomains(&self) {
        self.subdomains.iter().for_each(|subdomain| {
            println!("{}", subdomain.name);
        });
    }
}

pub async fn resolve_ip(domain: &str) -> Result<IpAddr, DomainError> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf().map_err(|e| DomainError {
        message: format!("Failed to create resolver: {}", e),
    })?;

    let response = resolver.lookup_ip(domain).await.map_err(|e| DomainError {
        message: format!("DNS lookup failed: {}", e),
    })?;

    if let Some(address) = response.iter().next() {
        Ok(address)
    } else {
        Err(DomainError {
            message: format!("No IP found for {}", domain),
        })
    }
}

pub async fn resolve_ip_fallback(domain: &str) -> Result<IpAddr, DomainError> {
    // will resolve using system fallback if needed

    let resolver = AsyncResolver::tokio_from_system_conf().unwrap();
    let response = resolver.lookup_ip(domain).await.expect("DNS Lookup failed");

    let address = response
        .iter()
        .next()
        .ok_or(format!("No IP found for {}", domain))?;

    return Ok(address);
}

pub async fn enumerate(target: &str, http_client: &Client) -> Result<Vec<Subdomain>, DomainError> {
    let entries: Vec<QueryEntry> = http_client
        .get(&format!("https://crt.sh/?Identity={}&output=json", target))
        .send()
        .await?
        .json()
        .await?;

    let mut subdomains: HashSet<String> = entries
        .into_iter()
        .map(|entry| {
            entry
                .name_value
                .split("\n")
                .map(|subdomain| subdomain.trim().to_string())
                .collect::<Vec<String>>()
        })
        .flatten()
        .filter(|subdomain: &String| subdomain != target)
        .filter(|subdomain: &String| subdomain.contains("*"))
        .collect();
    subdomains.insert(target.to_string());

    let mut resolved_subdomains = Vec::new();

    for domain in subdomains.into_iter() {
        let ip = resolve_ip(&domain).await?;
        resolved_subdomains.push(Subdomain {
            name: domain,
            main_domain: target.to_string(),
            associated_ip: ip,
        });
    }

    Ok(resolved_subdomains)
}
