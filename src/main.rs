mod utils;

use actix_web::{ get, web, App, HttpRequest, HttpResponse, HttpServer, Responder };
use clap::{ error::ErrorKind, CommandFactory, Parser };
use lazy_static::lazy_static;
use local_ip_address::local_ip;
use serde_urlencoded::from_str;
use serde_yaml::Value as YamlValue;
use utils::{ build, config, qrcode };

const SPECIFICATION: &str = include_str!("../使用说明.txt");

/// 基于HTTP传输协议的vless+ws[+tls]、trojan+ws[+tls]转换v2ray、sing-box、clash订阅工具!
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    /// HTTP服务器的端口
    #[arg(short, long, default_value = "10111")]
    port: u16,

    /// 默认转换为v2ray，可选singbox、clash
    #[arg(long, default_value = "v2ray")]
    target: String,
}

// 共享Args结构体中的数据状态（让Args在其它地方使用）
struct AppState {
    args: Args,
}

#[derive(Default, Clone)]
pub struct Params {
    pub target: String,
    pub node_count: usize,
    pub default_port: u16,
    pub userid: u8,
    pub column_name: String,
    pub template: bool,
    pub proxy_type: String,
    pub tls_mode: String,
    pub data_source: String,
}

lazy_static! {
    static ref CONFIG_FILE: &'static str = "config.yaml";
    static ref CLASH_TEMPLATE: &'static str = "template/clash.yaml";
    static ref SINGBOX_TEMPLATE: &'static str = "template/sing-box.json";
}

async fn default_route() -> impl Responder {
    HttpResponse::NotFound().body("Not found.")
}

#[get("/")]
async fn index(req: HttpRequest) -> impl Responder {
    let host_address = req.connection_info().host().to_owned();

    let html_body = SPECIFICATION.replace("127.0.0.1:10111", &host_address);

    // 获取当前局域网IP地址
    let ip_address = local_ip().unwrap().to_string();

    // 获取当前URL
    let url = format!(
        "{}://{}{}",
        req.connection_info().scheme(),
        req.connection_info().host().replace("127.0.0.1", &ip_address),
        req.uri()
    );

    // 生成二维码并将html_body嵌入网页中
    let html_content = qrcode::generate_html_with_qrcode(&html_body, &url);

    HttpResponse::Ok().content_type("text/html; charset=utf-8").body(html_content)
}

#[get("/sub")]
async fn subconverter(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let query_str = req.query_string();
    let params: Vec<(String, String)> = from_str(&query_str).expect("Failed to parse query string");

    let mut params_control = Params {
        target: data.args.target.to_string(), // 由cli参数中传递进来，默认转换为v2ray，可以在订阅链接中修改
        node_count: 300, // 节点数量，这里默认300，实际不一定是这个数字
        default_port: 0, // 默认端口，没有在数据文件读取到端口才启用它，0为随机端口
        userid: 0, // 选择yaml中哪个节点配置（index）
        column_name: "colo".to_string(), // 使用哪个列名的字段值为节点的前缀？可选：[colo,loc,region,city]
        template: true, // 是否使用模板文件，默认使用
        proxy_type: "all".to_string(), // 不区分代理的类型（vles、trojan）
        tls_mode: "all".to_string(), // 选择哪些端口？true/1是选择TLS端口，false/0选择非TLS的端口，其它就不区分
        data_source: "./data".to_string(), // 默认数据文件路径
    };

    // 获取url的参数
    for (key, value) in params {
        if key.to_lowercase() == "target" {
            params_control.target = value.to_string().to_string();
        } else if
            key.to_lowercase() == "n" ||
            key.to_lowercase() == "nodesize" ||
            key.to_lowercase() == "nodecount"
        {
            params_control.node_count = value.parse::<usize>().unwrap_or(params_control.node_count);
        } else if key.to_lowercase() == "dport" || key.to_lowercase() == "defaultport" {
            if let Ok(input_port) = value.parse::<u16>() {
                if (80..65535).contains(&input_port) {
                    params_control.default_port = input_port;
                }
            }
        } else if key.to_lowercase() == "tls" || key.to_lowercase() == "tlsmode" {
            match value.to_string().to_lowercase().as_str() {
                "1" | "true" => {
                    params_control.tls_mode = "true".to_string();
                }
                "0" | "false" => {
                    params_control.tls_mode = "false".to_string();
                }
                _ => {}
            }
        } else if
            key.to_lowercase() == "type" ||
            key.to_lowercase() == "proxy" ||
            key.to_lowercase() == "proxytype"
        {
            // 选择那种协议的配置节点？是vless还是trojan
            match value.to_string().to_lowercase().as_str() {
                "vless" => {
                    params_control.proxy_type = "vless".to_string();
                }
                "trojan" => {
                    params_control.proxy_type = "trojan".to_string();
                }
                _ => {}
            }
        } else if key.to_lowercase() == "id" || key.to_lowercase() == "userid" {
            if let Ok(1..=255) = value.parse::<u8>() {
                params_control.userid = value.parse::<u8>().unwrap();
            }
        } else if key.to_lowercase() == "template" {
            params_control.template = value.parse::<bool>().unwrap_or(true);
        } else if key.to_lowercase() == "column" || key.to_lowercase() == "columnname" {
            // 以哪个列的字段名作为前缀？[colo,loc,region,city]
            params_control.column_name = value.to_string();
        } else if key.to_lowercase() == "source" || key.to_lowercase() == "datasource" {
            params_control.data_source = value.to_string(); // 数据文件路径，支持相对路径和绝对路径
        }
    }

    // 限制节点数量
    if params_control.target == "singbox" && params_control.node_count > 150 {
        params_control.node_count = 50;
    } else if params_control.target == "clash" && params_control.node_count > 150 {
        params_control.node_count = 100;
    }

    let proxies_value: YamlValue = config::get_yaml_proxies(&CONFIG_FILE);

    // 分拣数据以及创建订阅内容
    let html_body = build::sorting_data_and_build_subscribe(
        proxies_value,
        params_control.clone(),
        &CLASH_TEMPLATE,
        &SINGBOX_TEMPLATE
    );

    HttpResponse::Ok().content_type("text/plain; charset=utf-8").body(html_body)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 获取命令行参数
    let result = Args::try_parse();
    match result {
        Ok(args) => {
            // 将args的cli参数值分享/传递给subconverter函数中使用
            let shared_state = web::Data::new(AppState { args: args.clone() });
            // 获取本机的私有IP地址
            let local_ip = match local_ip() {
                Ok(ip) => ip,
                Err(e) => {
                    eprintln!("Failed to get local IP address: {}", e);
                    return Ok(());
                }
            };
            // 绑定的端口
            let port = args.port;
            println!(
                "Server is running on http://{}:{} or http://127.0.0.1:{}",
                local_ip.to_string(),
                port,
                port
            );
            return HttpServer::new(move || {
                App::new()
                    .app_data(shared_state.clone())
                    .service(index)
                    .service(subconverter)
                    .default_service(actix_web::web::route().to(default_route))
            })
                .bind(format!("0.0.0.0:{}", port))?
                .run().await;
        }
        Err(e) => {
            if
                e.kind() == ErrorKind::MissingRequiredArgument ||
                e.kind() == ErrorKind::InvalidValue
            {
                // 如果是因为缺少必需参数或无效值导致的错误，则显示帮助信息
                Args::command().print_help().unwrap();
            } else {
                // 其他类型的错误则正常打印错误信息
                e.print().unwrap();
            }
        }
    }
    return Ok(());
}
