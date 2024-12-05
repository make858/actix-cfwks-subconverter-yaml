use crate::utils::{ clash, config, singbox, v2ray };
use rand::{ seq::SliceRandom, Rng };
use serde_yaml::Value as YamlValue;
use lazy_static::lazy_static;

lazy_static! {
    static ref HTTP_PORTS: [u16; 7] = [80, 8080, 8880, 2052, 2082, 2086, 2095];
    static ref HTTPS_PORTS: [u16; 6] = [443, 2053, 2083, 2087, 2096, 8443];
}

pub fn subconvert(
    alias_prefix: String,
    address: String,
    mut port: u16,
    yamlvalue: YamlValue,
    target: String,
    proxy_type: String,
    tls_mode: String,
    userid: u8
) -> (String, String) {
    // 判断端口类型的闭包
    let is_https_ports = move |port: u16| -> bool { HTTPS_PORTS.contains(&port) };
    let is_http_ports = move |port: u16| -> bool { HTTP_PORTS.contains(&port) };

    let alias_prefix_new = if alias_prefix.is_empty() {
        "".to_string()
    } else {
        format!("{} | ", alias_prefix)
    };
    if let Some(sequence) = yamlvalue.clone().as_sequence_mut() {
        let length = sequence.len();
        let mut index;

        // 循环200次，直到选中合适的节点配置为止，或循环200次才跳出循环
        for _ in 0..200 {
            let random_https_port = HTTPS_PORTS.choose(&mut rand::thread_rng()).unwrap_or(&443);
            let random_http_port: &u16 = HTTP_PORTS.choose(&mut rand::thread_rng()).unwrap_or(
                &8080
            );

            index = match (1..=(length + 1) as u8).contains(&userid) {
                true => (userid as usize) - 1, // 选择指定的账号（数组的下标）
                false => rand::thread_rng().gen_range(0..length), // 随机选择账号（数组的下标）
            };

            // 获取选择的节点信息（配置文件数组的下标）
            if let Some(yaml_value) = sequence.get_mut(index) {
                // 从配置文件中，获取到的代理类型
                let cptype = yaml_value
                    .get("type")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_lowercase())
                    .unwrap_or_default();

                let (_, host) = config::get_path_and_host_value(yaml_value);
                let is_workers_dev = host.ends_with("workers.dev");

                /*
                 * 处理 port 、 workers.dev 的端口问题，端口不对就随机生成一个
                 */
                if (!is_workers_dev && port == 0) || (!is_workers_dev && is_http_ports(port)) {
                    port = *random_https_port;
                } else if (is_workers_dev && port == 0) || (is_workers_dev && is_https_ports(port)) {
                    port = *random_http_port;
                }

                /*
                 * 处理 tls_mode 与 port 冲突问题
                 */
                if
                    (is_http_ports(port) && tls_mode == "true") ||
                    (is_https_ports(port) && tls_mode == "false")
                {
                    continue;
                }

                if proxy_type == cptype || proxy_type == "all" {
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
                        alias_prefix_new,
                        address,
                        port
                    );

                    match target.as_str() {
                        "v2ray" => {
                            match cptype.as_str() {
                                "vless" => {
                                    let vless_link = v2ray::build_vless_link(
                                        yaml_value,
                                        remarks.clone(),
                                        address,
                                        port
                                    );
                                    return (remarks, vless_link); // 前面是节点名称，后面是节点配置
                                }
                                "trojan" => {
                                    let trojan_link = v2ray::build_trojan_linnk(
                                        yaml_value,
                                        remarks.clone(),
                                        address,
                                        port
                                    );
                                    return (remarks, trojan_link); // 前面是节点名称，后面是节点配置
                                }
                                _ => {}
                            }
                        }
                        "clash" => {
                            let mut yaml_value_clone = yaml_value.clone();
                            let clash_node = clash::build_clash_json(
                                &mut yaml_value_clone,
                                remarks.clone(),
                                address,
                                port
                            );
                            let json_node: String = serde_json::to_string(&clash_node).unwrap();
                            let clash_with_prefix = format!("  - {json_node}");
                            return (remarks, clash_with_prefix); // 前面是节点名称，后面是节点配置
                        }
                        "singbox" => {
                            match cptype.as_str() {
                                "vless" => {
                                    let (remarks_name, vless_singbox) =
                                        singbox::build_vless_singbox_config(
                                            yaml_value,
                                            remarks,
                                            &address,
                                            port
                                        );
                                    return (remarks_name, vless_singbox);
                                }
                                "trojan" => {
                                    let (remarks_name, trojan_singbox) =
                                        singbox::build_trojan_singbox_config(
                                            yaml_value,
                                            remarks,
                                            &address,
                                            port
                                        );
                                    return (remarks_name, trojan_singbox);
                                }
                                _ => {}
                            }
                        }

                        _ => {}
                    }

                    break;
                }
            }
        }
    } else {
        println!("不是序列，config.yaml文件的书写格式有问题，请检查！");
    }

    // 返回的前面是节点名称，后面是节点配置
    return ("".to_string(), "".to_string());
}
