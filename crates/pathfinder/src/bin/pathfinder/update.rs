//! Discover pathfinder releases via github API.

/// Monitors Github for new releases and logs when this occurs.
///
/// Will continuously log this with every poll so that the user
/// has a better chance of spotting it.
pub async fn poll_github_for_releases() -> anyhow::Result<()> {
    use anyhow::Context;
    let current_version = pathfinder_common::consts::VERGEN_GIT_SEMVER_LIGHTWEIGHT;
    let current_version = current_version.strip_prefix('v').unwrap_or(current_version);
    let local_version = semver::Version::parse(current_version)
        .context("Semver parsing of local version failed")?;
    let mut latest_gh_version = None;
    let mut etag = None;

    let client = configure_client()?;

    loop {
        match fetch_latest_github_release(&client, &etag).await {
            UpdateResult::Update(release) => {
                etag = release.etag;

                let release_version = release
                    .version
                    .strip_prefix('v')
                    .unwrap_or(&release.version);
                match semver::Version::parse(release_version) {
                    Ok(version) => {
                        latest_gh_version = Some(version);
                    }
                    Err(e) => {
                        tracing::warn!(error=%e, version=%release.version, "Semver parsing of latest github release failed")
                    }
                };
            }
            UpdateResult::NotModified => {
                tracing::trace!(latest=?latest_gh_version, "No new release found on Github");
            }
            UpdateResult::ReqwestError(e) if e.is_decode() || e.is_body() || e.is_builder() => {
                // More severe errors, probably indicating something is wrong with our setup.
                // Set to warn and not error because this update checking is a non-critical feature.
                tracing::warn!(error=%e, "Error checking Github for new releases")
            }
            UpdateResult::ReqwestError(e) => {
                // Less severe errors, includes transient connection errors and timeouts; does not warrant
                // a high log level.
                tracing::trace!(error=%e, "Error checking Github for new releases")
            }
            UpdateResult::Other(e) => {
                // Other, unexpected errors.
                tracing::warn!(error=%e, "Error checking Github for new releases");
            }
        }

        // Display latest release info if it is newer than this application.
        if let Some(github) = latest_gh_version.as_ref() {
            if github > &local_version {
                tracing::warn!(release=%github, "New pathfinder release available! Please consider updating your node!")
            }
        }

        // Only poll every 10 minutes.
        tokio::time::sleep(std::time::Duration::from_secs(60 * 10)).await;
    }
}

/// Creates a [reqwest::Client] for use in querying Github API.
///
/// Adds a 5 minute request timeout, and sets the required headers:
/// - [ACCEPT](https://docs.github.com/en/rest/overview/resources-in-the-rest-api#current-version)
/// - [USER_AGENT](https://docs.github.com/en/rest/overview/resources-in-the-rest-api#user-agent-required)
fn configure_client() -> anyhow::Result<reqwest::Client> {
    use anyhow::Context;
    let mut headers = reqwest::header::HeaderMap::new();
    // https://docs.github.com/en/rest/overview/resources-in-the-rest-api#current-version
    headers.insert(
        reqwest::header::ACCEPT,
        "application/vnd.github.v3+json".parse().unwrap(),
    );

    reqwest::Client::builder()
        .default_headers(headers)
        // https://docs.github.com/en/rest/overview/resources-in-the-rest-api#user-agent-required
        .user_agent(pathfinder_common::consts::USER_AGENT)
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .context("Failed to create Github client")
}

#[derive(Debug)]
struct Release {
    version: String,
    /// Optional because its possible to have an invalid string ETag header.
    etag: Option<reqwest::header::HeaderValue>,
}

#[derive(Debug)]
enum UpdateResult {
    /// A new latest release.
    Update(Release),
    /// No new releases since last query (status code 304).
    NotModified,
    ReqwestError(reqwest::Error),
    Other(anyhow::Error),
}

/// Fetches the latest pathfinder [Release] from Github using their REST API.
///
/// The [IF_NONE_MATCH](reqwest::header::IF_NONE_MATCH) header options is set to
/// the `etag` parameter to prevent Github from sending redundant information. The
/// resulting 304 status code is mapped to [UpdateResult::NotModified].
async fn fetch_latest_github_release(
    client: &reqwest::Client,
    etag: &Option<reqwest::header::HeaderValue>,
) -> UpdateResult {
    use reqwest::StatusCode;
    use reqwest::Url;

    let url = Url::parse("https://api.github.com/repos/eqlabs/pathfinder/releases/latest").unwrap();

    let mut request = client.get(url);

    if let Some(etag) = etag {
        request = request.header(reqwest::header::IF_NONE_MATCH, etag);
    }

    let result = match request.send().await {
        Ok(r) => r,
        Err(e) => return UpdateResult::ReqwestError(e),
    };
    match result.status() {
        StatusCode::NOT_MODIFIED => UpdateResult::NotModified,
        StatusCode::OK => {
            #[derive(serde::Deserialize)]
            struct JsonRelease {
                name: String,
            }

            let etag = result.headers().get(reqwest::header::ETAG).cloned();

            match result.json::<JsonRelease>().await {
                Ok(r) => UpdateResult::Update(Release {
                    version: r.name,
                    etag,
                }),
                Err(e) => UpdateResult::ReqwestError(e),
            }
        }
        other => UpdateResult::Other(anyhow::anyhow!(
            "Unexpected response status code: {}",
            other
        )),
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn fetch_latest_github_release() {
        let client = super::configure_client().unwrap();

        // First check should result in the latest github release.
        let release = super::fetch_latest_github_release(&client, &None).await;
        use super::UpdateResult;
        let release = match release {
            UpdateResult::Update(r) => r,
            other => panic!("Expected an update, but got {other:?}"),
        };

        // Second check should result in no new update (as etag is set to latest release).
        let etag = release.etag.expect("etag should be set");
        let not_modified = super::fetch_latest_github_release(&client, &Some(etag)).await;
        assert_matches::assert_matches!(not_modified, UpdateResult::NotModified);
    }
}
