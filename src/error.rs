use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
  #[error("the maximum poll attempts have been exceeded")]
  MaxAttemptsExceeded,

  #[error("validation error: {0}")]
  Validation(&'static str),

  #[error(transparent)]
  Server(#[from] ServerError),

  #[error(transparent)]
  Transport(Box<dyn std::error::Error>),

  #[error(transparent)]
  Other(Box<dyn std::error::Error>),
}

#[derive(Debug, thiserror::Error)]
#[error("transport error: {0}")]
pub struct TransportError(&'static str);

pub fn transport_err(msg: &'static str) -> Error {
  Error::Transport(Box::new(TransportError(msg)))
}

pub fn map_transport_err<T, E: std::error::Error + 'static>(
  res: Result<T, E>,
) -> Result<T, Error> {
  res.map_err(|err| Error::Transport(Box::new(err)))
}

impl From<reqwest::Error> for Error {
  fn from(err: reqwest::Error) -> Self {
    Self::Transport(Box::new(err))
  }
}

impl From<serde_json::Error> for Error {
  fn from(err: serde_json::Error) -> Self {
    Self::Transport(Box::new(err))
  }
}

impl From<openssl::error::ErrorStack> for Error {
  fn from(err: openssl::error::ErrorStack) -> Self {
    Self::Other(Box::new(err))
  }
}

/// The result of an operation that can return a [`ServerError`].
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum ServerResult<T> {
  Ok(T),
  Err(ServerError),
}

impl<T> Into<Result<T, Error>> for ServerResult<T> {
  fn into(self) -> Result<T, Error> {
    match self {
      ServerResult::Ok(t) => Ok(t),
      ServerResult::Err(err) => Err(err.into()),
    }
  }
}
/// This is an error as returned by the ACME server.
#[derive(Deserialize, Debug, Clone, thiserror::Error)]
#[serde(rename_all = "camelCase")]
#[error("ServerError({}): {}: {}", r#type.clone().unwrap_or_default(), title.clone().unwrap_or_default(), detail.clone().unwrap_or_default())]
pub struct ServerError {
  /// The type of this error.
  pub r#type: Option<String>,
  /// The human readable title of this error.
  pub title: Option<String>,
  /// The status code of this error.
  pub status: Option<u16>,
  /// The human readable extra description for this error.
  pub detail: Option<String>,
}
