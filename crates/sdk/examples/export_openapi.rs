fn main() {
    #[cfg(feature = "server")]
    {
        let document = contrix::openapi_document();
        println!(
            "{}",
            serde_json::to_string_pretty(&document).expect("serialize OpenAPI document")
        );
    }

    #[cfg(not(feature = "server"))]
    {
        eprintln!("enable the `server` feature to export OpenAPI");
        std::process::exit(1);
    }
}
