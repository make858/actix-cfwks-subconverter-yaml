use super::config::{ get_yaml_value, get_yaml_value_with_fallback };
use serde_json::{ json, Value as JsonValue };
use serde_yaml::Value as YamlValue;
use std::collections::HashMap;

pub fn build_singbox_config_json(
    proxy_type: &str,
    yaml_value: &mut YamlValue,
    remarks: String,
    server_address: String,
    server_port: u16
) -> (String, String) {
    match proxy_type {
        "vless" => {
            let (remarks_name, vless_singbox) = build_vless_singbox_config(
                yaml_value,
                remarks,
                server_address,
                server_port
            );
            return (remarks_name, vless_singbox);
        }
        "trojan" => {
            let (remarks_name, trojan_singbox) = build_trojan_singbox_config(
                yaml_value,
                remarks,
                server_address,
                server_port
            );
            return (remarks_name, trojan_singbox);
        }
        "ss" => {
            let (remarks_name, ss_singbox) = build_ss_singbox_config(
                yaml_value,
                remarks,
                server_address,
                server_port
            );
            return (remarks_name, ss_singbox);
        }
        _ => {}
    }

    return (String::new(), String::new());
}

fn build_ss_singbox_config(
    yaml_value: &mut YamlValue,
    remarks: String,
    server_address: String,
    server_port: u16
) -> (String, String) {
    let path = get_yaml_value(&yaml_value, &["plugin-opts", "path"])
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let host = get_yaml_value(&yaml_value, &["plugin-opts", "host"])
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let password = get_yaml_value(&yaml_value, &["password"])
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let plugin_value = format!("tls;mux=0;mode=websocket;path={};host={}", path, host);

    let singbox_ss_json_str =
        r#"{
        "type": "shadowsocks",
        "tag": "",
        "server": "",
        "server_port": 443,
        "method": "none",
        "password": "",
        "plugin": "v2ray-plugin",
        "plugin_opts": ""
    }"#;

    let mut ss_jsonvalue: JsonValue = serde_json::from_str(singbox_ss_json_str).unwrap_or_default();

    ss_jsonvalue["server"] = json!(server_address);
    ss_jsonvalue["server_port"] = json!(server_port);
    ss_jsonvalue["password"] = json!(password);
    ss_jsonvalue["plugin_opts"] = json!(plugin_value);
    ss_jsonvalue["tag"] = json!(remarks.clone());

    let json_string = serde_json::to_string_pretty(&ss_jsonvalue).unwrap_or_default();

    return (remarks, json_string);
}

fn build_vless_singbox_config(
    yaml_value: &mut YamlValue,
    remarks: String,
    server_address: String,
    server_port: u16
) -> (String, String) {
    let uuid = get_yaml_value(&yaml_value, &["uuid"])
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

    let tls_server_name = get_yaml_value_with_fallback(
        &yaml_value,
        &["servername", "sni"]
    ).unwrap_or_default();

    let vless_singbox_config =
        r#"{
        "type": "vless",
        "tag": "vless_tag",
        "server": "",
        "server_port": 443,
        "uuid": "",
        "network": "tcp",
        "tls": {
            "enabled": true,
            "server_name": "",
            "insecure": true,
            "utls": {
                "enabled": true,
                "fingerprint": "chrome"
            }
        },
        "transport": {
            "type": "ws",
            "path": "/",
            "headers": {"Host": ""},
            "early_data_header_name": "Sec-WebSocket-Protocol"
        }
    }"#;

    let mut jsonvalue: JsonValue = serde_json::from_str(vless_singbox_config).unwrap_or_default();

    let outer_updates = HashMap::from([
        ("tag", json!(remarks)),
        ("server", json!(server_address)),
        ("server_port", json!(server_port)),
        ("uuid", json!(uuid)),
    ]);

    let result: JsonValue = update_singbox_json_value(
        &mut jsonvalue,
        outer_updates,
        host.to_string(),
        path.to_string(),
        tls_server_name.to_string(),
        client_fingerprint.to_string()
    );

    let json_string = serde_json::to_string_pretty(&result).unwrap_or_default();

    return (remarks, json_string);
}

fn build_trojan_singbox_config(
    yaml_value: &mut YamlValue,
    remarks: String,
    server_address: String,
    server_port: u16
) -> (String, String) {
    let password = get_yaml_value(&yaml_value, &["password"])
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

    let tls_server_name = get_yaml_value_with_fallback(
        &yaml_value,
        &["sni", "servername"]
    ).unwrap_or_default();

    let trojan_singbox_config =
        r#"{
        "type": "trojan",
        "tag": "tag_name",
        "server": "",
        "server_port": 443,
        "password": "",
        "network": "tcp",
        "tls": {
            "enabled": true,
            "server_name": "",
            "insecure": true,
            "utls": {
                "enabled": true,
                "fingerprint": "chrome"
            }
        },
        "transport": {
            "type": "ws",
            "path": "/",
            "headers": {"Host": ""},
            "early_data_header_name": "Sec-WebSocket-Protocol"
        }
    }"#;

    let mut jsonvalue: JsonValue = serde_json::from_str(trojan_singbox_config).unwrap_or_default();

    let outer_updates = HashMap::from([
        ("tag", json!(remarks)),
        ("server", json!(server_address)),
        ("server_port", json!(server_port)),
        ("password", json!(password)),
    ]);

    let result: JsonValue = update_singbox_json_value(
        &mut jsonvalue,
        outer_updates,
        host.to_string(),
        path.to_string(),
        tls_server_name.to_string(),
        client_fingerprint.to_string()
    );

    let json_string = serde_json::to_string_pretty(&result).unwrap_or_default();

    return (remarks, json_string);
}

fn update_singbox_json_value(
    jsonvalue: &mut JsonValue,
    outer_updates: HashMap<&str, JsonValue>,
    host: String,
    path: String,
    tls_server_name: String,
    client_fingerprint: String
) -> JsonValue {
    // 修改jsonvalue的外层字段（多个字段）
    for (key, new_value) in outer_updates {
        if let Some(outer_value) = jsonvalue.get_mut(key) {
            *outer_value = new_value;
        }
    }
    // 修改jsonvalue的tls字段
    if let Some(tls) = jsonvalue.get_mut("tls") {
        if let Some(server_name) = tls.get_mut("server_name") {
            *server_name = json!(tls_server_name);
        }
        // 手动关闭tls
        if host.ends_with("workers.dev") {
            if let Some(tls_enabled) = tls.get_mut("enabled") {
                *tls_enabled = json!(false);
            }
        }
        if let Some(utls) = tls.get_mut("utls") {
            if let Some(fingerprint) = utls.get_mut("fingerprint") {
                *fingerprint = json!(client_fingerprint);
            }
        }
    }
    // 修改jsonvalue的transport字段
    if let Some(transport) = jsonvalue.get_mut("transport") {
        if let Some(path_value) = transport.get_mut("path") {
            *path_value = json!(path);
        }
        if let Some(headers) = transport.get_mut("headers") {
            if let Some(host_value) = headers.get_mut("Host") {
                *host_value = json!(host);
            }
        }
    }

    jsonvalue.clone()
}
