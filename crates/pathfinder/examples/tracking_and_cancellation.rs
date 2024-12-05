use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    eprintln!("\n\nStart");

    let task_tracker = TaskTracker::new();
    let cancellation_token = CancellationToken::new();

    let ct1 = cancellation_token.clone();
    let ct2 = cancellation_token.clone();
    let ct3 = cancellation_token.clone();

    let fut1 = async {
        loop {
            eprintln!("Task 1 going to sleep...");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    };
    let fut2 = async {
        loop {
            eprintln!("Task 2 going to sleep...");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    };

    let _jh1 = task_tracker.spawn(async move {
        tokio::select! {
            _ = ct1.cancelled() => {
                eprintln!("Task 1 cancelled");
            }
            _ = fut1 => {
                eprintln!("Task 1 completed");
            }
        }
    });
    let _jh2 = task_tracker.spawn(async move {
        tokio::select! {
            _ = ct2.cancelled() => {
                eprintln!("Task 2 cancelled");
            }
            _ = fut2 => {
                eprintln!("Task 2 completed");
            }
        }
    });
    let _jh3 = task_tracker.spawn_blocking(move || {
        loop {
            if ct3.is_cancelled() {
                eprintln!("Task 3 cancelled");
                return;
            }

            eprintln!("Task 3 going to sleep...");
            std::thread::sleep(Duration::from_secs(1));
        }
        #[allow(unreachable_code)]
        {
            eprintln!("Task 3 completed");
        }
    });

    tokio::time::sleep(Duration::from_millis(2500)).await;

    eprintln!("Shutting down...");
    eprintln!("   Closing task tracker...");

    task_tracker.close();

    eprintln!("   Cancelling tasks...");

    cancellation_token.cancel();

    eprintln!("   Waiting for tasks to finish...");

    task_tracker.wait().await;
    // the above code is equivalent to the following:
    // let _ = tokio::join!(_jh1, _jh2, _jh3);

    Ok(())
}
