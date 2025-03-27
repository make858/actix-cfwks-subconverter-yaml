use super::{ clash, config::get_yaml_value, singbox, v2ray };
use rand::{ seq::SliceRandom, Rng };
use serde_yaml::Value as YamlValue;
use lazy_static::lazy_static;

lazy_static! {
    static ref HTTP_PORTS: [u16; 7] = [80, 8080, 8880, 2052, 2082, 2086, 2095];
    static ref HTTPS_PORTS: [u16; 6] = [443, 2053, 2083, 2087, 2096, 8443];
}

pub fn subconvert(
    csv_alias: String,
    csv_addr: String,
    mut port: u16,
    yamlvalue: YamlValue,
    uri_target: String,
    uri_proxy_type: String,
    uri_tls_mode: String,
    uri_userid: u8
) -> (String, String) {
    // 判断端口类型的闭包
    let is_https_ports = move |port: u16| -> bool { HTTPS_PORTS.contains(&port) };
    let is_http_ports = move |port: u16| -> bool { HTTP_PORTS.contains(&port) };

    let csv_remarks = match csv_alias.is_empty() {
        true => String::new(),
        false => format!("{} | ", csv_alias),
    };
    if let Some(sequence) = yamlvalue.clone().as_sequence_mut() {
        let length = sequence.len();
        let mut index;

        // 循环200次，直到选中合适的节点配置为止，或循环200次才跳出循环
        for _ in 0..200 {
            // 使用config.yaml中具体哪个节点的配置
            index = match (1..=(length + 1) as u8).contains(&uri_userid) {
                true => (uri_userid as usize) - 1, // 选择指定的（数组的下标）
                false => rand::thread_rng().gen_range(0..length), // 随机选择（数组的下标）
            };

            let random_https_port = HTTPS_PORTS.choose(&mut rand::thread_rng()).unwrap_or(&443);
            let random_http_port = HTTP_PORTS.choose(&mut rand::thread_rng()).unwrap_or(&8080);

            if let Some(yaml_value) = sequence.get_mut(index) {
                let mut yaml_value_clone = yaml_value.clone();

                let node_type = yaml_value_clone
                    .get("type")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(String::new);
                let host = match node_type.as_str() {
                    "ss" =>
                        get_yaml_value(&yaml_value_clone, &["plugin-opts", "host"])
                            .and_then(|v| v.as_str())
                            .unwrap_or_default(),
                    "vless" | "trojan" =>
                        get_yaml_value(&yaml_value_clone, &["ws-opts", "headers", "Host"])
                            .and_then(|v| v.as_str())
                            .unwrap_or_default(),
                    _ => {
                        continue;
                    }
                };

                let is_workers_dev = host.ends_with("workers.dev");

                // 处理 port 、 workers.dev 的端口问题，端口不对就随机生成一个
                if
                    (!is_workers_dev && port == 0) ||
                    (!is_workers_dev && is_http_ports(port)) ||
                    (node_type == "ss" && is_http_ports(port))
                {
                    port = *random_https_port;
                } else if (is_workers_dev && port == 0) || (is_workers_dev && is_https_ports(port)) {
                    port = *random_http_port;
                }
                // 处理 port 冲突问题（不支持所选的这个节点配置）
                if
                    (is_http_ports(port) && uri_tls_mode == "true") ||
                    (is_https_ports(port) && uri_tls_mode == "false") ||
                    (node_type == "ss" && is_http_ports(port))
                {
                    continue;
                }

                if uri_proxy_type == node_type || uri_proxy_type == "all" {
                    // 节点序号/账号的序号(从1开始)
                    let padded_index = format!(
                        "{:0width$}",
                        index + 1,
                        width = length.to_string().len()
                    );
                    // 构建完整的节点名称
                    let remarks: String = format!(
                        "【{}】{}{}:{}",
                        padded_index,
                        csv_remarks,
                        csv_addr.clone(),
                        port
                    );
                    match uri_target.as_str() {
                        "v2ray" => {
                            let (remarks_name, link) = v2ray::build_v2ray_links(
                                &node_type,
                                &mut yaml_value_clone,
                                remarks,
                                csv_addr,
                                port
                            );
                            if !remarks_name.is_empty() {
                                return (remarks_name, link);
                            }
                        }
                        "clash" => {
                            let clash_node = clash::build_clash_yaml(
                                &mut yaml_value_clone,
                                remarks.clone(),
                                csv_addr,
                                port
                            );
                            let json_node: String = serde_json::to_string(&clash_node).unwrap();
                            let json_string = format!("  - {json_node}");
                            return (remarks, json_string);
                        }
                        "singbox" => {
                            let (remarks_name, json_string) = singbox::build_singbox_config_json(
                                &node_type,
                                &mut yaml_value_clone,
                                remarks,
                                csv_addr,
                                port
                            );
                            if !remarks_name.is_empty() {
                                return (remarks_name, json_string);
                            }
                        }

                        _ => {}
                    }

                    break;
                }
            }
        }
    }

    // 返回的前面是节点名称，后面是节点配置
    return (String::new(), String::new());
}
