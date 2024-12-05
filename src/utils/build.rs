use crate::{ utils::{ convert, file, file_data, net_data }, Params };
use regex::Regex;
use serde_yaml::Value as YamlValue;
use serde_json::json;
use lazy_static::lazy_static;

lazy_static! {
    // 匹配包含 "name:" 的 "- {}" 字符串，应用到clash相关代码中
    static ref PROXYIES_NAME_REGEX: Regex = Regex::new(
        r"  - \{([^}]*(name:[^}]*)[^}]*)\}"
    ).unwrap();
}

/// 分拣数据以及创建订阅内容
pub fn sorting_data_and_build_subscribe(
    yamlvalue: YamlValue,
    params_control: Params,
    clash_template: &str,
    singbox_template: &str
) -> String {
    // 针对win11中"复制文件地址"出现双引号的情况
    let trimmed_quotes_path = params_control.data_source.trim_matches('"');

    // 获取数据(网络数据/本地数据)
    let my_datas = if trimmed_quotes_path.to_lowercase().starts_with("https://") {
        // 传入的一个https://链接，就从网络获取数据
        net_data::process_network_data(
            &params_control.column_name,
            params_control.default_port,
            params_control.node_count,
            trimmed_quotes_path
        )
    } else {
        // 传入的是本地文件路径，就从本地获取数据
        file_data::process_files_data(
            &params_control.column_name, // 获取指定字段的数据作为节点别名的前缀
            params_control.default_port, // 没有找到端口的情况，就使用它
            params_control.node_count, // 获取指定数量的数据就返回
            trimmed_quotes_path // 指定数据源所在文件夹路径或文件路径
        )
    };

    // 没有数据，就返回空字符串
    if my_datas.is_empty() {
        return "".to_string();
    }

    // 下面的代码块，通过不同的转换，获取节点名称和节点配置或v2ray链接
    let mut proxy_name_vec = Vec::new();
    let mut nodes_vec = Vec::new();
    for item in &my_datas {
        let alias_prefix = item.alias.clone().unwrap_or("".to_string());
        let addr = item.addr.clone();
        let port = item.port.unwrap_or(params_control.default_port);
        let (proxy_name, node) = convert::subconvert(
            alias_prefix,
            addr,
            port,
            yamlvalue.clone(),
            params_control.target.clone(),
            params_control.proxy_type.clone(),
            params_control.tls_mode.clone(),
            params_control.userid.clone()
        );
        if !node.is_empty() && !nodes_vec.contains(&node) {
            nodes_vec.push(node);
        }
        if
            !proxy_name.is_empty() &&
            vec!["clash", "singbox"].contains(&params_control.target.as_str()) &&
            !proxy_name_vec.contains(&proxy_name)
        {
            proxy_name_vec.push(proxy_name);
        }
    }

    // 防止没有nodes_vec数据
    if nodes_vec.is_empty() {
        return "".to_string();
    }

    // 前面获取到数据后，开始构建完整的配置文件订阅（或分享链接订阅）
    let full_subscribe = build_full_subscribe(
        params_control.target,
        params_control.template,
        proxy_name_vec,
        nodes_vec,
        clash_template,
        singbox_template
    );

    full_subscribe
}

/// 将生成的nodes_vec节点信息，构建完整的订阅（或分享链接订阅）
fn build_full_subscribe(
    target: String,
    enable_template: bool,
    proxy_name_vec: Vec<String>,
    nodes_vec: Vec<String>,
    clash_template: &str,
    singbox_template: &str
) -> String {
    let mut html_body = String::new();
    match target.as_str() {
        "clash" => {
            match enable_template {
                true => {
                    // 读取模板文件
                    let clash_template_content: String = file::read_file_to_string(&clash_template);
                    // 替换模板文件中的内容
                    if !proxy_name_vec.is_empty() && !clash_template_content.is_empty() {
                        html_body = PROXYIES_NAME_REGEX.replace_all(
                            &clash_template_content,
                            &nodes_vec.join("\n")
                        ).replace(
                            "      - 127.0.0.1:1080",
                            &proxy_name_vec
                                .clone()
                                .iter_mut()
                                .map(|name| format!("      - {}", name))
                                .collect::<Vec<String>>()
                                .join("\n")
                        );
                    }
                }
                false => {
                    html_body = format!("proxies:\n{}", nodes_vec.join("\n"));
                }
            }
        }
        "singbox" => {
            match enable_template {
                true => {
                    // 读取模板文件以及解析为JSON
                    let singbox_json: serde_json::Value = serde_json
                        ::from_str(&file::read_file_to_string(&singbox_template))
                        .unwrap_or(serde_json::Value::Null);
                    // 运用插入/retain()等操作修改模板文件的内容
                    if !proxy_name_vec.is_empty() && singbox_json.is_object() {
                        let mut singbox_config = singbox_json.clone();
                        if let Some(outbounds) = singbox_config["outbounds"].as_array_mut() {
                            // 将节点插入到outbounds中
                            for json_str in &nodes_vec {
                                let parsed_json = serde_json
                                    ::from_str(json_str)
                                    .expect("Failed to parse JSON");
                                outbounds.insert(2, parsed_json); // 插入到第3个位置
                            }
                            outbounds.iter_mut().for_each(|item| {
                                if let Some(obj) = item.as_object_mut() {
                                    obj.get_mut("outbounds")
                                        .and_then(serde_json::Value::as_array_mut)
                                        .map(|inside_outbounds| {
                                            // 使用 retain 方法来过滤掉 "{all}"
                                            inside_outbounds.retain(
                                                |x| x.as_str() != Some("{all}")
                                            );
                                            // 添加 proxy_name 到内层的 outbounds 中
                                            inside_outbounds.extend(
                                                proxy_name_vec
                                                    .iter()
                                                    .map(|s| serde_json::Value::String(s.clone()))
                                            );
                                        });
                                }
                            });
                        }
                        html_body = serde_json::to_string_pretty(&singbox_config).unwrap();
                    }
                }
                false => {
                    let mut outbounds = json!({"outbounds": []});
                    if let Some(array) = outbounds["outbounds"].as_array_mut() {
                        nodes_vec.iter().for_each(|name| {
                            array.push(serde_json::from_str(name).unwrap());
                        });
                    }
                    html_body = serde_json::to_string_pretty(&outbounds).unwrap();
                }
            }
        }
        _ => {
            html_body = nodes_vec.join("\n"); // 视为v2ray订阅的分享链接
        }
    }

    html_body
}
