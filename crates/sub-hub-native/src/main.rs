#[tokio::main]
async fn main() -> std::process::ExitCode {
    match sub_hub_native::NativeConfig::from_environment() {
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
        Ok(config) => match sub_hub_native::serve(config).await {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{}", sub_hub_native::RunError::from(error));
                std::process::ExitCode::FAILURE
            }
        },
    }
}
