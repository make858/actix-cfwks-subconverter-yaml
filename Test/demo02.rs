use csv::ReaderBuilder;
use reqwest;
use std::{ collections::HashMap, error::Error, thread };
use crossbeam_channel::unbounded; // 需要引入 crossbeam-channel 库
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // 匹配一个或多个空白字符
    static ref SPACE_REGEX: Regex = Regex::new(r"\s+").unwrap();
    // 匹配"IPv4 PORT"（可以1个以上的空格）
    static ref IPV4_PORT_SPACE_REGEX: Regex = Regex::new(r"^\s*([0-9.]+)\s+(\d+)\s*$").unwrap();
    // 匹配"IPv6 PORT"（可以1个以上的空格）
    static ref IPV6_PORT_SPACE_REGEX: Regex = Regex::new(
        r"^\s*((([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])))\s*"
    ).unwrap();
    // 匹配"[IPv6]:PORT"
    static ref IPV6_PORT_BRACKET_REGEX: Regex = Regex::new(
        r"^\s*\[([0-9a-fA-F:.]+)\]:(\d+)\s*$"
    ).unwrap();
    // 匹配"IPv6,PORT"（逗号左右可以零个以上的空格）
    static ref IPV6_PORT_COMMA_REGEX: Regex = Regex::new(
        r"([0-9a-fA-F:]+:[0-9a-fA-F:]+)\s*,\s*(\d+)"
    ).unwrap();
}

// 1. 定义数据结构 (假设你的 CSV 有两列：name 和 age)
#[derive(Default)]
pub struct FileData {
    pub addr: String, // IP地址或者域名地址
    pub port: Option<u16>,
    pub colo: Option<String>, // 数据中心(3位字母)
    pub loc: Option<String>, // 国家代码/地区代码(2位字母)
    pub region: Option<String>, // 地区
    pub city: Option<String>,
}

#[derive(Default, Clone)]
pub struct MyData {
    pub addr: String,
    pub port: Option<u16>,
    pub alias: Option<String>,
}

// 同步函数中使用异步：使用 std::thread::spawn 在另一个线程中运行异步代码
fn read_csv_from_url(
    url: &str,
    default_port: u16
) -> Result<Vec<FileData>, Box<dyn Error + Send + Sync>> {
    let (sender, receiver) = unbounded();
    let url_copy = url.to_string();

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            let response = reqwest::get(&url_copy).await?;
            if !response.status().is_success() {
                return Err(format!("Failed to fetch CSV from URL: {}", response.status()).into());
            }
            let body = response.text().await?;
            let mut rdr = ReaderBuilder::new().from_reader(body.as_bytes());
            let headers = rdr.headers()?; // 读取并忽略头部

            // 可能的字段映射关系，以列名作为键，其它别名的列名作为值(向量)
            let mut field_map: HashMap<&str, Vec<&str>> = HashMap::new();
            field_map.insert("addr", vec!["IP", "IP地址", "IP 地址", "网络地址"]);
            field_map.insert("port", vec!["PORT", "端口"]);
            field_map.insert("colo", vec!["colo", "iata", "数据中心"]);
            field_map.insert(
                "loc",
                vec!["cca2", "alpha-2", "Country Code", "CountryCode", "国家代码"]
            );
            field_map.insert("region", vec!["region", "区域", "地区"]);
            field_map.insert("city", vec!["city", "城市"]);

            // 尝试从标题中查找列索引(下标)
            let find_index = |key: &str| {
                field_map.get(key).and_then(|candidates|
                    candidates.iter().find_map(|&field|
                        headers.iter().position(
                            |header| header.trim().to_lowercase() == field.trim().to_lowercase() // 忽略字段中的大小写
                        )
                    )
                )
            };
            // 找csv标题的列名跟向量中哪个元素对应 => 在哪个索引(下标)中
            let addr_index = find_index("addr");
            let port_index = find_index("port");
            let colo_index = find_index("colo");
            let loc_index = find_index("loc");
            let region_index = find_index("region");
            let city_index = find_index("city");

            // 2. 修改异步代码，将 CSV 记录转换为结构体实例，并收集到向量
            let mut records: Vec<FileData> = Vec::new();

            for record in rdr.records() {
                let record = record?;

                // 获取`IP地址`字段的值
                let addr_column = addr_index.and_then(|index| record.get(index)).unwrap_or("");

                if addr_column.is_empty() {
                    continue;
                }

                // 获取`端口`字段的值
                let port_column: u16 = port_index
                    .and_then(|index| record.get(index).and_then(|val| val.parse::<u16>().ok())) // 显示转换
                    .unwrap_or(default_port); // 默认为`default_port`

                // 定义一个闭包来处理列的提取逻辑(只支持String数据类型的数据提取)
                let get_column_string = |index: Option<usize>| {
                    index
                        .and_then(|idx| record.get(idx).and_then(|val| val.parse().ok())) // 隐式转换
                        .unwrap_or_else(|| "".to_string()) // 默认为空字符串
                };

                // 使用闭包提取列数据，没有找到对应的列时，返回空字符串
                let colo_column = get_column_string(colo_index);
                let loc_column = get_column_string(loc_index);
                let region_column = get_column_string(region_index);
                let city_column = get_column_string(city_index);

                let data = FileData {
                    addr: addr_column.to_string(),
                    port: Some(port_column),
                    colo: Some(colo_column),
                    loc: Some(loc_column),
                    region: Some(region_column),
                    city: Some(city_column),
                };
                records.push(data);
            }
            Ok(records) // 返回向量
        });
        sender.send(result).unwrap();
    });

    // 4. 通过通道发送结果
    receiver.recv().unwrap() // 接收通道中的向量
}

fn read_txt_from_url(
    url: &str,
    default_port: u16
) -> Result<Vec<FileData>, Box<dyn Error + Send + Sync>> {
    let (sender, receiver) = unbounded();
    let url_copy = url.to_string();
    let mut seen_lines: Vec<String> = Vec::new();
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            let response = reqwest::get(&url_copy).await?;
            if !response.status().is_success() {
                return Err(format!("Failed to fetch CSV from URL: {}", response.status()).into());
            }
            let body = response.text().await?;
            let mut records: Vec<FileData> = Vec::new();
            for line in body.lines() {
                let trimmed_line = line.trim().to_string();

                if
                    trimmed_line.is_empty() ||
                    trimmed_line.contains("/") || // 跳过包含"/"的行 => CIDR
                    seen_lines.contains(&trimmed_line)
                {
                    continue;
                }

                // 提取地址和端口
                let parts: Vec<String> = if
                    let Some(captures) = IPV6_PORT_COMMA_REGEX.captures(&trimmed_line)
                {
                    // 判断是否为 "IPv6, PORT" 格式(逗号左右，可以0个以上的空格)
                    let ipv6 = captures.get(1).map_or("", |m| m.as_str());
                    let port = captures.get(2).map_or("", |m| m.as_str());
                    vec![format!("[{}]", ipv6), port.to_string()]
                } else if IPV6_PORT_SPACE_REGEX.is_match(&trimmed_line) {
                    // 判断是否为 "IPv6 PORT" 地址
                    SPACE_REGEX.splitn(&trimmed_line, 2)
                        .map(|s| {
                            let str_s = s.to_string();
                            let colon_count = str_s
                                .chars()
                                .filter(|&c| c == ':')
                                .count();
                            if colon_count > 1 {
                                if str_s.starts_with('[') && str_s.ends_with(']') {
                                    str_s // 已经有方括号，直接返回
                                } else {
                                    format!("[{}]", str_s) // 添加方括号
                                }
                            } else {
                                str_s // 不满足条件，直接返回
                            }
                        })
                        .collect()
                } else if let Some(captures) = IPV6_PORT_BRACKET_REGEX.captures(&trimmed_line) {
                    // 判断是否为 "[IPv6]:PORT" 格式
                    vec![
                        format!("[{}]", captures.get(1).unwrap().as_str().to_string()),
                        captures.get(2).unwrap().as_str().to_string()
                    ]
                } else if let Some(captures) = IPV4_PORT_SPACE_REGEX.captures(&trimmed_line) {
                    // 判断是否为 "IPv4 PORT" 格式
                    vec![
                        captures.get(1).unwrap().as_str().to_string(),
                        captures.get(2).unwrap().as_str().to_string()
                    ]
                } else if
                    trimmed_line.contains(':') &&
                    trimmed_line
                        .chars()
                        .filter(|&c| c == ':')
                        .count() == 1
                {
                    // 判断是否为 "IPv4:PORT" 或 "Domain:PORT" 格式
                    trimmed_line
                        .splitn(2, ':')
                        .map(|s| s.to_string())
                        .collect()
                } else if trimmed_line.contains(", ") {
                    // 判断是否为 "IPv4, PORT" 、"[IPv6], PORT"、" "Domain, PORT" 格式
                    trimmed_line
                        .splitn(2, ", ")
                        .map(|s| s.to_string())
                        .collect()
                } else if trimmed_line.contains(',') {
                    // 判断是否为 "IPv4,PORT" 、"[IPv6],PORT"、" "Domain,PORT" 格式
                    trimmed_line
                        .splitn(2, ',')
                        .map(|s| s.to_string())
                        .collect()
                } else if SPACE_REGEX.is_match(&trimmed_line) {
                    // 判断是否为 "[IPv6] PORT" 或 "Domain PORT" 格式
                    let value = SPACE_REGEX.splitn(&trimmed_line, 2)
                        .map(|s| s.to_string())
                        .collect();
                    value
                } else {
                    // 匹配 "IPv4"、"[ipv6]"、"Domain" 格式
                    vec![trimmed_line.to_string(), default_port.to_string()]
                };

                if parts.len() == 2 {
                    let final_line = format!("{}:{}", parts[0], parts[1]);
                    if !seen_lines.contains(&final_line) {
                        let data = FileData {
                            addr: parts[0].clone(),
                            port: parts[1].parse::<u16>().ok(),
                            ..Default::default() // 其它字段不管，使用默认值
                        };
                        seen_lines.push(final_line);
                        records.push(data);
                    }
                } else {
                    println!("不支持提取 `{}` 的地址和端口！", trimmed_line);
                }
            }
            Ok(records)
        });
        sender.send(result).unwrap();
    });

    receiver.recv().unwrap()
}

fn process_network_data(
    field_column: &str,
    default_port: u16,
    count: usize,
    url: &str
) -> Vec<MyData> {
    let mut results: Vec<MyData> = Vec::new(); // 存储结果
    let mut seen_addr = Vec::new();

    if url.to_lowercase().starts_with("https://") && url.to_lowercase().ends_with(".csv") {
        match read_csv_from_url(url, default_port) {
            Ok(data) => {
                for item in &data {
                    let addr: String = item.addr.clone();
                    let port: u16 = item.port.unwrap_or(default_port);
                    let addr_port = format!("{}:{}", addr, port);

                    // 数据去重，确保获取到数据没有重复的
                    if seen_addr.contains(&addr_port) {
                        continue;
                    } else {
                        seen_addr.push(addr_port.clone());
                    }

                    // 获取某个字段值作为节点的别名前缀使用，注意，找不到对应的字段，则默认为空值，后面需要做处理
                    let alias_prefix = match field_column {
                        "colo" => item.colo.clone(),
                        "loc" => item.loc.clone(),
                        "region" => item.region.clone(),
                        "city" => item.city.clone(),
                        _ => Some("".to_string()),
                    };

                    // （选择性）将需要的字段值，以MyData结构体形式存储
                    let data = MyData {
                        addr: addr.clone(),
                        port: Some(port),
                        alias: alias_prefix,
                    };

                    // 如果结果数量小于指定的数量，则添加数据，否则就返回，避免无意义的IO操作(读取数据)
                    if results.len() < count {
                        results.push(data.clone());
                    } else {
                        break;
                    }
                }
            }
            Err(e) => eprintln!("Error: {}", e),
        }
    } else if url.to_lowercase().starts_with("https://") && url.to_lowercase().ends_with(".txt") {
        match read_txt_from_url(url, default_port) {
            Ok(data) => {
                for item in &data {
                    let addr: String = item.addr.clone();
                    let port: u16 = item.port.unwrap_or(default_port);
                    let addr_port = format!("{}:{}", addr, port);

                    // 数据去重，确保获取到数据没有重复的
                    if seen_addr.contains(&addr_port) {
                        continue;
                    } else {
                        seen_addr.push(addr_port.clone());
                    }

                    // 获取某个字段值作为节点的别名前缀使用，注意，找不到对应的字段，则默认为空值，后面需要做处理
                    let alias_prefix = match field_column {
                        "colo" => item.colo.clone(),
                        "loc" => item.loc.clone(),
                        "region" => item.region.clone(),
                        "city" => item.city.clone(),
                        _ => Some("".to_string()),
                    };

                    // （选择性）将需要的字段值，以MyData结构体形式存储
                    let data = MyData {
                        addr: addr.clone(),
                        port: Some(port),
                        alias: alias_prefix,
                    };

                    // 如果结果数量小于指定的数量，则添加数据，否则就返回，避免无意义的IO操作(读取数据)
                    if results.len() < count {
                        results.push(data.clone());
                    } else {
                        break;
                    }
                }
            }
            Err(e) => eprintln!("Error: {}", e),
        }
    }

    results
}

fn main() {
    let count = 100;
    let default_port = 443;
    let field_column = "colo";
    let url =
        "https://raw.githubusercontent.com/juerson/actix-cfwks-subconverter-yaml/refs/heads/master/data/result.csv";
    // let url =
    //     "https://raw.githubusercontent.com/juerson/wireguard_converted_nekoray/refs/heads/main/ip.txt";

    let my_data = process_network_data(field_column, default_port, count, url);

    println!("{:?}", my_data.len());

    for item in my_data {
        let addr = item.addr.to_string();
        let port = item.port.unwrap_or(default_port);
        let alias = item.alias.unwrap_or("".to_string());
        println!("addr: {}, port: {} alias: {}", addr, port, alias);
    }
}
