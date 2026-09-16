//! Keep native hook regressions from leaving a hung child/CI runner behind.
#[cfg(unix)]
pub fn status(command: &mut std::process::Command) -> std::process::ExitStatus {
    let mut child = command.spawn().expect("spawn native fixture");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().expect("poll native fixture") {
            return status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("native fixture exceeded 20 seconds: {command:?}");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
