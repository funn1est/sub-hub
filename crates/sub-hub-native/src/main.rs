#[tokio::main]
async fn main() -> std::process::ExitCode {
    let result = match sub_hub_native::NativeConfig::from_environment() {
        Ok(config) => sub_hub_native::serve(config).await,
        Err(error) => Err(error.into()),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
