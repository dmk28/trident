use regex::Regex;
use reqwest::Client;
use std::io;
use std::net::IpAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[derive(Debug)]
pub struct BannerError {
    message: String,
}
impl From<std::io::Error> for BannerError {
    fn from(err: std::io::Error) -> Self {
        BannerError {
            message: format!("IO ERROR {}", err),
        }
    }
}

impl From<reqwest::Error> for BannerError {
    fn from(err: reqwest::Error) -> Self {
        BannerError {
            message: format!("HTTP ERROR: {}", err),
        }
    }
}

impl From<reqwest::header::ToStrError> for BannerError {
    fn from(err: reqwest::header::ToStrError) -> Self {
        BannerError {
            message: format!("Header conversion error: {}", err),
        }
    }
}

pub struct ServiceProbe {
    pub name: String,
    pub probe_data: Vec<u8>,
    pub match_pattern: Regex,
    pub default_ports: Vec<u16>,
}
#[derive(Debug)]
pub struct ServiceInfo {
    // sometimes, services will refuse or withhold either vresion or service name, thus we need to make these Options.
    pub name: Option<String>,
    pub version: Option<String>,
    pub confidence: Option<f32>,
    pub port: u16,
    pub raw_banner: Option<String>,
}
// POFs if we need to create more services later.

#[derive(Debug, Clone)]
pub struct ConversationStep {
    pub probe_data: Vec<u8>,
    pub expected_patterns: Vec<Regex>,
    pub next_step_logic: fn(&str) -> Option<usize>,
}

#[derive(Debug, Clone)]
pub struct ConversationProbe {
    pub name: String,
    pub steps: Vec<ConversationStep>,
    pub initial_step: usize,
    pub completion_patterns: Vec<Regex>,
    pub default_ports: Vec<u16>,
}

#[derive(Debug)]
pub struct ConversationResult {
    pub service_info: ServiceInfo,
    pub conversation_log: Vec<(String, String)>,
    pub discovered_capabilities: Vec<String>,
    pub conversation_complete: bool,
}

pub async fn grab_ssh_banner(ip: IpAddr, port: u16) -> Result<String, BannerError> {
    let stream = TcpStream::connect((ip, port)).await?;

    let mut msg = vec![0; 1024];

    loop {
        stream.readable().await?;

        match stream.try_read(&mut msg) {
            Ok(n) => {
                if msg.starts_with(b"SSH-") {
                    msg.truncate(n);
                    break;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
    let banner = String::from_utf8_lossy(&msg).to_string();
    println!("BANNER: {:?}", banner);
    Ok(banner)
}

pub async fn grab_ftp_banner(ip: IpAddr, port: u16) -> Result<String, BannerError> {
    let stream = TcpStream::connect((ip, port)).await?;
    let mut msg = vec![0; 1024];

    loop {
        stream.readable().await?;

        match stream.try_read(&mut msg) {
            Ok(n) => {
                if msg.starts_with(b"220") {
                    msg.truncate(n);
                    break;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }

            Err(e) => {
                return Err(e.into());
            }
        }
    }

    let banner = String::from_utf8_lossy(&msg).to_string();
    println!("BANNER: {:?}", banner);
    Ok(banner)
}

//for HTTP we should keep this one as it does not use Tokio but reqwest and is superior to it regardless.
pub async fn grab_http_banner(
    ip: IpAddr,
    port: u16,
    hostname: Option<&str>,
) -> Result<String, BannerError> {
    let ip_string = ip.to_string();

    let host = hostname.unwrap_or(&ip_string);

    let url = if port == 443 || port == 8443 {
        format!("https://{}:{}", host, port)
    } else {
        format!("http://{}:{}", host, port)
    };

    let client = Client::new();

    let response = client.get(&url).send().await?;

    match response.headers().get("server") {
        Some(server_header) => Ok(server_header.to_str()?.to_string()),
        None => Ok("No Server Header".to_string()),
    }
}

// dynamic detector
//

async fn try_probe(
    ip: IpAddr,
    port: u16,
    probe: &ServiceProbe,
) -> Result<Option<ServiceInfo>, BannerError> {
    let http_ports: Vec<u16> = [443, 80, 8080, 4443, 44443]
        .iter()
        .map(|&port| port as u16)
        .collect();
    if http_ports.contains(&port) {
        let evaluation = grab_http_banner(ip, port, None).await?;
        if !evaluation.is_empty() {
            let service_info = ServiceInfo {
                name: Some(evaluation.clone()),
                version: None,
                confidence: Some(1.0),
                port,
                raw_banner: Some(evaluation),
            };

            return Ok(Some(service_info));
        }
    };

    let mut stream = TcpStream::connect((ip, port)).await?;

    if !probe.probe_data.is_empty() {
        stream.write_all(&probe.probe_data).await?;
    }

    let mut buffer = vec![0; 2048];

    stream.readable().await?;

    let n = stream.try_read(&mut buffer)?;

    let response = String::from_utf8_lossy(&buffer[..n]);

    let captures = probe.match_pattern.captures(&response);

    match captures {
        Some(captures) => {
            let version = captures.get(1).map(|m| m.as_str().to_string());

            Ok(Some(ServiceInfo {
                name: Some(probe.name.clone()),
                version,
                confidence: Some(0.9),
                port,
                raw_banner: Some(response.to_string()),
            }))
        }

        _ => Err(BannerError {
            message: "No service detected".to_string(),
        }),
    }
}

pub async fn detect_service(
    ip: IpAddr,
    port: u16,
    probes: &[ServiceProbe],
) -> Result<ServiceInfo, BannerError> {
    for probe in probes {
        match try_probe(ip, port, probe).await {
            Ok(Some(service_info)) => return Ok(service_info),
            Ok(_) => continue,
            Err(_) => continue,
        }
    }

    Err(BannerError {
        message: "No service detected".to_string(),
    })
}

pub struct ActiveConversation {
    stream: TcpStream,
    probe: ConversationProbe,
    current_step: usize,
    result: ConversationResult,
}

impl ActiveConversation {
    pub async fn new(ip: IpAddr, port: u16, probe: ConversationProbe) -> Result<Self, BannerError> {
        let stream = TcpStream::connect((ip, port)).await?;

        let result = ConversationResult {
            service_info: ServiceInfo {
                name: Some(probe.name.clone()),
                version: None,
                confidence: Some(0.9),
                port,
                raw_banner: None,
            },
            conversation_log: Vec::new(),
            discovered_capabilities: Vec::new(),
            conversation_complete: false,
        };

        Ok(ActiveConversation {
            stream,
            probe: probe.clone(),
            current_step: probe.initial_step,
            result,
        })
    }

    pub async fn execute_step(&mut self) -> Result<bool, BannerError> {
        let step = &self.probe.steps[self.current_step];

        if !step.probe_data.is_empty() {
            self.stream.write_all(&step.probe_data).await?;
            let sent = String::from_utf8_lossy(&step.probe_data).to_string();

            println!("SENT: {}", sent.trim());
        }

        let mut buffer = vec![0; 2048];
        self.stream.readable().await?;
        let n = self.stream.try_read(&mut buffer)?;
        let response = String::from_utf8_lossy(&buffer[..n]).to_string();

        println!("RECEIVED: {}", response.trim());

        self.result.conversation_log.push((
            String::from_utf8_lossy(&step.probe_data).to_string(),
            response.clone(),
        ));

        let mut pattern_matched = false;
        for pattern in &step.expected_patterns {
            if let Some(captures) = pattern.captures(&response) {
                pattern_matched = true;

                if let Some(version_match) = captures.get(1) {
                    if self.result.service_info.version.is_none() {
                        self.result.service_info.version = Some(version_match.as_str().to_string());
                    }

                    if response.contains("250-") {
                        for line in response.lines() {
                            if line.starts_with("250-") || line.starts_with("250") {
                                let capability = line[4..].trim().to_string();
                                if !capability.is_empty() {
                                    self.result.discovered_capabilities.push(capability);
                                }
                            }
                        }
                    }
                }

                break;
            }
        }

        if !pattern_matched {
            return Ok(false);
        }

        if let Some(next_step) = (step.next_step_logic)(&response) {
            self.current_step = next_step;
            Ok(true)
        } else {
            self.result.conversation_complete = true;
            self.result.service_info.confidence = Some(0.95);
            Ok(false)
        }
    }

    pub async fn run_conversation(mut self) -> Result<ConversationResult, BannerError> {
        while !self.result.conversation_complete {
            match self.execute_step().await {
                Ok(true) => continue,
                Ok(false) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(self.result)
    }
}

fn create_smtp_conversation() -> ConversationProbe {
    ConversationProbe {
        name: "SMTP".to_string(),
        steps: vec![
            ConversationStep {
                probe_data: vec![],
                expected_patterns: vec![Regex::new(r"220 (.+)").unwrap()],
                next_step_logic: |response| {
                    if response.contains("220") {
                        Some(1)
                    } else {
                        None
                    }
                },
            },
            ConversationStep {
                probe_data: b"HELO test.com\r\n".to_vec(),
                expected_patterns: vec![Regex::new(r"250 (.+)").unwrap()],
                next_step_logic: |response| {
                    if response.contains("250") {
                        Some(2)
                    } else {
                        None
                    }
                },
            },
            ConversationStep {
                probe_data: b"EHLO test.com\r\n".to_vec(),
                expected_patterns: vec![
                    Regex::new(r"250-(.+)").unwrap(),
                    Regex::new(r"250 (.+)").unwrap(),
                ],
                next_step_logic: |_response| None,
            },
        ],
        initial_step: 0,
        completion_patterns: vec![Regex::new(r"250 HELP").unwrap()],
        default_ports: vec![25, 587, 465],
    }
}

pub async fn run_smtp_conversation(
    ip: IpAddr,
    port: u16,
) -> Result<ConversationResult, BannerError> {
    let probe = create_smtp_conversation();
    let conversation = ActiveConversation::new(ip, port, probe).await?;
    conversation.run_conversation().await
}
