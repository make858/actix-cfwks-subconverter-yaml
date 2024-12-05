use crate::utils::config;
use serde_qs as qs;
use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;

pub fn build_vless_link(
    yaml_value: &mut YamlValue,
    set_remarks: String,
    set_server: String,
    set_port: u16
) -> String {
    let uuid = config::get_field_value(yaml_value, "uuid");
    let network = config::get_field_value(yaml_value, "network");
    let client_fingerprint = config::get_field_value(yaml_value, "client-fingerprint");

    let sni = config::get_sni_or_servename_value(yaml_value);
    let security = config::get_vless_tls_value(yaml_value);
    let (path, host) = config::get_path_and_host_value(yaml_value);
    let alpn = config::get_alpn_value(yaml_value);

    let encoding_alpn = urlencoding::encode(&alpn);
    let encoding_path = urlencoding::encode(&path);
    let encoding_remarks = urlencoding::encode(set_remarks.as_str());

    let mut params = BTreeMap::new();
    params.insert("encryption", "none");
    params.insert("security", &security);
    params.insert("type", &network);
    params.insert("host", &host);
    params.insert("path", &encoding_path);
    params.insert("sni", &sni);
    params.insert("alpn", &encoding_alpn);
    params.insert("fp", &client_fingerprint);
    params.insert("allowInsecure", "1");

    // 过滤掉值为空的键值对，然后将数据结构序列化为Query String格式的字符串
    let all_params_str = serialize_to_query_string(params);

    let vless_link = format!(
        "vless://{uuid}@{set_server}:{set_port}/?{all_params_str}#{encoding_remarks}"
    );
    vless_link
}

pub fn build_trojan_linnk(
    yaml_value: &mut YamlValue,
    set_remarks: String,
    set_server: String,
    set_port: u16
) -> String {
    let password = config::get_field_value(yaml_value, "password");
    let network = config::get_field_value(yaml_value, "network");
    let client_fingerprint = config::get_field_value(yaml_value, "client-fingerprint");

    let sni = config::get_sni_or_servename_value(yaml_value);
    let (path, host) = config::get_path_and_host_value(yaml_value);
    let alpn = config::get_alpn_value(yaml_value);

    // url编码
    let encoding_alpn = urlencoding::encode(&alpn);
    let encoding_path = urlencoding::encode(&path);
    let encoding_remarks = urlencoding::encode(&set_remarks);

    let security = match host.ends_with("workers.dev") {
        true => "none",
        false => "tls",
    };

    // 构建节点链接后面的参数
    let mut params = BTreeMap::new();
    params.insert("security", security);
    params.insert("sni", &sni);
    params.insert("alpn", &encoding_alpn);
    params.insert("fp", &client_fingerprint);
    params.insert("type", &network);
    params.insert("host", &host);
    params.insert("path", &encoding_path);
    params.insert("allowInsecure", "1");

    // 过滤掉值为空的键值对，然后将数据结构序列化为Query String格式的字符串
    let all_params_str = serialize_to_query_string(params);

    let trojan_link = format!(
        "trojan://{password}@{set_server}:{set_port}/?{all_params_str}#{encoding_remarks}"
    );
    trojan_link
}

fn serialize_to_query_string(params: BTreeMap<&str, &str>) -> String {
    let filtered_params: BTreeMap<_, _> = params
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .collect();
    let all_params_str = qs::to_string(&filtered_params).unwrap();
    all_params_str
}
