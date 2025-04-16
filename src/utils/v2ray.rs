use super::config::{get_yaml_value, get_yaml_value_with_fallback};
use serde_qs as qs;
use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;

pub fn build_v2ray_links(
    proxy_type: &str,
    yaml_value: &mut YamlValue,
    remarks: String,
    server_address: String,
    server_port: u16,
) -> (String, String) {
    match proxy_type {
        "vless" => {
            let vless_link =
                build_vless_link(yaml_value, remarks.clone(), server_address, server_port);
            return (remarks, vless_link); // 前面是节点名称，后面是节点配置
        }
        "trojan" => {
            let trojan_link =
                build_trojan_linnk(yaml_value, remarks.clone(), server_address, server_port);
            return (remarks, trojan_link); // 前面是节点名称，后面是节点配置
        }
        "ss" => {
            let ss_link = build_ss_link(yaml_value, remarks.clone(), server_address, server_port);
            return (remarks, ss_link); // 前面是节点名称，后面是节点配置
        }
        _ => {}
    }
    return ("".to_string(), "".to_string());
}

fn build_ss_link(
    yaml_value: &mut YamlValue,
    remarks: String,
    server_address: String,
    server_port: u16,
) -> String {
    let path = get_yaml_value(&yaml_value, &["plugin-opts", "path"])
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let host = get_yaml_value(&yaml_value, &["plugin-opts", "host"])
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let tls_val = get_yaml_value(&yaml_value, &["plugin-opts", "tls"])
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let password = get_yaml_value(&yaml_value, &["password"])
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let base64_encoded = base64::encode(format!("none:{}", password).as_bytes());

    let insert_tls_str = match tls_val {
        true => format!("tls;"),
        false => format!(""),
    };

    let plugin = format!(
        "v2ray-plugin;{}mux=0;mode=websocket;path={};host={}",
        insert_tls_str, path, host
    )
    .replace("=", "%3D");

    let ss_link: String = format!(
        "ss://{}@{}:{}?plugin={}#{}",
        base64_encoded, server_address, server_port, plugin, remarks
    );
    ss_link
}

fn build_vless_link(
    yaml_value: &mut YamlValue,
    remarks: String,
    server_address: String,
    server_port: u16,
) -> String {
    let uuid = get_yaml_value(&yaml_value, &["uuid"])
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let network = get_yaml_value(&yaml_value, &["network"])
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let client_fingerprint = get_yaml_value(&yaml_value, &["client-fingerprint"])
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let path = get_yaml_value(&yaml_value, &["ws-opts", "path"])
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let host = get_yaml_value(&yaml_value, &["ws-opts", "headers", "Host"])
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    let sni = get_yaml_value_with_fallback(&yaml_value, &["sni", "servername"]).unwrap_or_default();
    let security = match host.ends_with("workers.dev") {
        true => "none",
        false => "tls",
    };

    let encoding_remarks = urlencoding::encode(remarks.as_str());

    let mut params = BTreeMap::new();
    params.insert("encryption", "none");
    params.insert("security", &security);
    params.insert("type", &network);
    params.insert("host", &host);
    params.insert("sni", &sni);
    params.insert("fp", &client_fingerprint);
    params.insert("allowInsecure", "1");
    params.insert("path", &path);

    // 过滤掉值为空的键值对，然后将数据结构序列化为Query String格式的字符串
    let all_params_str = serialize_to_query_string(params);

    let vless_link = format!(
        "vless://{uuid}@{server_address}:{server_port}/?{all_params_str}#{encoding_remarks}"
    );
    vless_link
}

fn build_trojan_linnk(
    yaml_value: &mut YamlValue,
    remarks: String,
    server_address: String,
    server_port: u16,
) -> String {
    let password = get_yaml_value(&yaml_value, &["password"])
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let network = get_yaml_value(&yaml_value, &["network"])
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let client_fingerprint = get_yaml_value(&yaml_value, &["client-fingerprint"])
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let path = get_yaml_value(&yaml_value, &["ws-opts", "path"])
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let host = get_yaml_value(&yaml_value, &["ws-opts", "headers", "Host"])
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    let sni = get_yaml_value_with_fallback(&yaml_value, &["sni", "servername"]).unwrap_or_default();
    let security = match host.ends_with("workers.dev") {
        true => "none",
        false => "tls",
    };

    let encoding_remarks = urlencoding::encode(&remarks);

    // 构建节点链接后面的参数
    let mut params = BTreeMap::new();
    params.insert("security", security);
    params.insert("sni", &sni);
    params.insert("fp", &client_fingerprint);
    params.insert("type", &network);
    params.insert("host", &host);
    params.insert("allowInsecure", "1");
    params.insert("path", &path);

    // 过滤掉值为空的键值对，然后将数据结构序列化为Query String格式的字符串
    let all_params_str = serialize_to_query_string(params);

    let trojan_link = format!(
        "trojan://{password}@{server_address}:{server_port}/?{all_params_str}#{encoding_remarks}"
    );
    trojan_link
}

fn serialize_to_query_string(params: BTreeMap<&str, &str>) -> String {
    let filtered_params: BTreeMap<_, _> =
        params.into_iter().filter(|(_, v)| !v.is_empty()).collect();
    let all_params_str = qs::to_string(&filtered_params).unwrap_or_default();
    all_params_str
}
