//! `token inspect` subcommand: print metadata about the access token.

use std::{
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use clap::Parser;
use humantime::format_duration;
use pimalaya_cli::printer::Printer;
use serde::Serialize;

use io_oauth::rfc6749::issue_access_token::Oauth20AccessTokenSuccessParams;

use crate::account::Account;

/// Inspect metadata associated to the access token.
///
/// Unlike the `token show` command, this command shows you metadata
/// like the token type, when it was issued, when it expires, the
/// presence of a refresh token, and the granted scopes.
#[derive(Debug, Parser)]
pub struct TokenInspectCommand;

impl TokenInspectCommand {
    /// Reads the token from storage and prints its metadata.
    pub fn execute(self, printer: &mut impl Printer, mut account: Account) -> Result<()> {
        let response = account.read_from_storage()?;
        printer.out(Report::from_params(response))
    }
}

/// Printable metadata view over the stored token response.
///
/// Holds only non-secret fields so human Display and `--json` agree:
/// neither path exposes the access or refresh token (use `token show`
/// for the access token).
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Report {
    token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    issued_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in: Option<usize>,
    with_refresh_token: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

impl Report {
    pub fn from_params(params: Oauth20AccessTokenSuccessParams) -> Self {
        Self {
            token_type: params.token_type,
            issued_at: params.issued_at,
            expires_in: params.expires_in,
            with_refresh_token: params.refresh_token.is_some(),
            scope: params.scope,
        }
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Token type: {}", self.token_type.to_lowercase())?;

        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .ok();

        if let (Some(issued_at), Some(now)) = (self.issued_at, now_epoch) {
            let elapsed = Duration::from_secs(now.saturating_sub(issued_at));
            writeln!(f)?;
            write!(f, "Issued: {} ago", format_duration(elapsed))?;
        }

        match self.expires_in {
            None => {
                writeln!(f)?;
                write!(f, "Expired: unknown")?;
            }
            Some(exp) => {
                let remaining = match (self.issued_at, now_epoch) {
                    (Some(issued_at), Some(now)) => (issued_at + exp as u64).saturating_sub(now),
                    _ => exp as u64,
                };
                writeln!(f)?;
                if remaining == 0 {
                    write!(f, "Expired: true")?;
                } else {
                    let duration = format_duration(Duration::from_secs(remaining));
                    write!(f, "Expires in: {duration}")?;
                }
            }
        }

        writeln!(f)?;
        write!(f, "With refresh token: {}", self.with_refresh_token)?;

        if let Some(scope) = &self.scope {
            writeln!(f)?;
            write!(f, "With scope: {scope}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;

    #[test]
    fn report_json_omits_access_and_refresh_tokens() {
        let report = Report::from_params(Oauth20AccessTokenSuccessParams {
            access_token: SecretString::from("access-token-must-not-leak"),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some(SecretString::from("refresh-token-must-not-leak")),
            scope: Some("mail".into()),
            issued_at: Some(1_700_000_000),
        });
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("access-token-must-not-leak"));
        assert!(!json.contains("refresh-token-must-not-leak"));
        assert!(!json.contains("access_token"));
        assert!(!json.contains("refresh_token"));
        assert!(json.contains("with-refresh-token"));
    }
}
