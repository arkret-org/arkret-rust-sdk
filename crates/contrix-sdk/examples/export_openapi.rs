#[cfg(feature = "server")]
fn main() {
    let document = contrix_sdk::openapi_document();
    println!("{}", serde_json::to_string_pretty(&document).expect("OpenAPI JSON"));
}

#[cfg(not(feature = "server"))]
fn main() {
    eprintln!("enable the `server` feature to export OpenAPI");
    std::process::exit(1);
}
