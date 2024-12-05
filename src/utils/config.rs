use serde_yaml::{ self, Value as YamlValue };
use std::{ fs::File, io::{ BufReader, Read } };

/// 将YAML文件解析为 serde_yaml::Value
pub fn get_yaml_proxies(file_path: &str) -> serde_yaml::Value {
    let file = File::open(file_path).expect("Failed to open file");
    let mut reader = BufReader::new(file);

    let mut yaml_content = String::new();
    reader.read_to_string(&mut yaml_content).expect("Failed to read YAML");

    let yaml_value: YamlValue = serde_yaml::from_str(&yaml_content).expect("Failed to parse YAML");

    // 检查顶层是否有 "proxies" 键
    if let Some(proxies_value) = yaml_value.get("proxies") {
        // 如果 "proxies" 键的值是序列，则直接返回该值
        if proxies_value.is_sequence() {
            return proxies_value.clone();
        }
    }

    yaml_value
}

/// 通用，只获取一级字段的值（同级）
pub fn get_field_value(yaml_value: &mut YamlValue, field_name: &str) -> String {
    let value = yaml_value
        .get(&YamlValue::String(field_name.to_string()))
        .and_then(YamlValue::as_str)
        .map_or("".to_string(), |value: &str| value.to_string());
    value
}

/// path字段和host字段
pub fn get_path_and_host_value(yaml_value: &mut YamlValue) -> (String, String) {
    let mut path = "".to_string();
    let mut host = "".to_string();
    if let Some(opts_mapping) = yaml_value.get("ws-opts").and_then(YamlValue::as_mapping) {
        path = opts_mapping
            .get("path")
            .and_then(YamlValue::as_str)
            .map_or("".to_string(), |value| value.to_string());
        let host_value = if
            let Some(header_mapping) = opts_mapping.get("headers").and_then(YamlValue::as_mapping)
        {
            match header_mapping.get("Host").and_then(YamlValue::as_str) {
                Some(value) => value.to_string(),
                None =>
                    match header_mapping.get("host").and_then(YamlValue::as_str) {
                        Some(value) => value.to_string(),
                        None => "".to_string(), // 默认值，如果没有找到任何字段
                    }
            }
        } else {
            "".to_string()
        };
        host = host_value.to_string();
    }
    (path, host)
}

/// tls字段(只针对vless)
pub fn get_vless_tls_value(yaml_value: &mut YamlValue) -> String {
    let security = yaml_value
        .get("tls")
        .and_then(YamlValue::as_bool)
        .map(|v| {
            match v {
                true => "tls".to_string(),
                false => "none".to_string(),
            }
        })
        .unwrap_or("none".to_string());

    security
}

/// sni字段或servername字段都视为同一个字段
pub fn get_sni_or_servename_value(yaml_value: &mut YamlValue) -> String {
    let sni = match yaml_value.get("sni").and_then(YamlValue::as_str) {
        Some(value) => value.to_string(),
        None => {
            match yaml_value.get("servername").and_then(YamlValue::as_str) {
                Some(value) => value.to_string(),
                None => "".to_string(), // 默认值，如果没有找到任何字段
            }
        }
    };
    sni
}

/// alpn字段
pub fn get_alpn_value(yaml_value: &mut YamlValue) -> String {
    let alpn = yaml_value
        .get("alpn")
        .and_then(YamlValue::as_sequence)
        .map_or("".to_string(), |alpn_value| {
            alpn_value
                .iter()
                .map(|v| v.as_str().unwrap_or("").to_string())
                .collect::<Vec<_>>()
                .join(",")
        });
    alpn
}
