use colored::Colorize;

/// Print a result in either JSON or human-readable format.
pub fn print_result(json_mode: bool, human_msg: &str, json_value: &serde_json::Value) {
    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(json_value).expect("JSON serialization cannot fail")
        );
    } else {
        println!("{}", human_msg);
    }
}

/// Print an error and exit-ready message.
pub fn print_error(json_mode: bool, msg: &str) {
    if json_mode {
        let err = serde_json::json!({"error": msg});
        eprintln!(
            "{}",
            serde_json::to_string(&err).expect("JSON serialization cannot fail")
        );
    } else {
        eprintln!("{} {}", "error:".red().bold(), msg);
    }
}
