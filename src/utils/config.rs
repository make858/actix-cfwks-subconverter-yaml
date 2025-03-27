use serde_yaml::{ self, Value as YamlValue };
use std::{ fs::File, io::{ BufReader, Read } };

// 将YAML文件解析为 serde_yaml::Value
pub fn parse_file_to_yamlvlaue(file_path: &str) -> YamlValue {
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => {
            return YamlValue::Null;
        }
    };
    let mut reader = BufReader::new(file);
    let mut yaml_content = String::new();

    if reader.read_to_string(&mut yaml_content).is_err() {
        return YamlValue::Null;
    }

    let yaml_value = serde_yaml::from_str(&yaml_content).unwrap_or(YamlValue::Null);

    yaml_value
        .get("proxies")
        .filter(|v| v.is_sequence()) // 只获取"proxies"键的值是序列的
        .cloned()
        .unwrap_or(yaml_value) // 如果没有找到"proxies"键，则返回整个yaml_value值
}

// 递归查找 YAML 值
pub fn get_yaml_value<'a>(yaml: &'a YamlValue, keys: &[&str]) -> Option<&'a YamlValue> {
    let mut current = yaml;
    for key in keys {
        // 查找忽略大小写的键
        current = current
            .as_mapping()?
            .iter()
            .find(|(k, _)| {
                k.as_str().map_or(false, |k_str| k_str.to_lowercase() == key.to_lowercase())
            })
            .map(|(_, v)| v)?;
    }
    Some(current)
}

// 多个keys备选查找函数
pub fn get_yaml_value_with_fallback<'a>(yaml: &'a YamlValue, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .filter_map(|&key| get_yaml_value(yaml, &[key]).and_then(|v| v.as_str()))
        .next()
}
