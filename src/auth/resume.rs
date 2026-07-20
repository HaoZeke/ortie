//! `auth resume` subcommand: complete an OAuth grant flow.

use std::{borrow::Cow, fmt};

use anyhow::{Result, anyhow, bail};
use clap::Parser;
use log::debug;
use pimalaya_cli::printer::Printer;
use secrecy::SecretString;
use serde::{
    Deserialize,
    de::value::{Error, StrDeserializer},
};
use url::Url;

use pimalaya_config::secret::Secret;

use io_oauth::{
    client::Oauth20ClientStd,
    rfc6749::{
        access_token_request::Oauth20AccessTokenRequestParams,
        auth_response::{Oauth20AuthParams, Oauth20AuthParamsValidationError},
        state::Oauth20State,
    },
    rfc7636::pkce::Oauth20PkceCodeVerifier,
    rfc8628::auth::Oauth20DeviceAuthSuccessParams,
};

use crate::{
    account::Account,
    auth::get::{complete_device_token_poll, report_token_issued},
    config::GrantConfig,
};

/// Resume an existing OAuth 2.0 grant flow.
///
/// Positional input is the redirected URI (authorization-code) or the
/// device code (device grant).
#[derive(Parser)]
pub struct AuthResumeCommand {
    /// Redirected URI or device code.
    #[arg(value_name = "URI|DEVICE_CODE")]
    pub input: String,

    /// CSRF state from auth get (authorization-code only).
    #[arg(long, short, value_parser = state_parser)]
    #[arg(value_name = "VALUE")]
    pub state: Option<Oauth20State>,

    /// PKCE verifier from auth get (authorization-code only).
    ///
    /// Stored as a plain string so clap cannot re-echo it on parse
    /// failure; validated into Oauth20PkceCodeVerifier in execute.
    #[arg(long, short)]
    #[arg(value_name = "CODE")]
    pub pkce: Option<String>,

    /// Redirect URI from auth get (authorization-code only).
    #[arg(long, short, value_parser = uri_parser)]
    pub redirect_uri: Option<Url>,
}

// Redact the positional input: device_code or redirect with code=.
// state / pkce already redact via SecretBox Debug.
impl fmt::Debug for AuthResumeCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthResumeCommand")
            .field("input", &"[REDACTED]")
            .field("state", &self.state)
            .field("pkce", &self.pkce.as_ref().map(|_| "[REDACTED]"))
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

impl AuthResumeCommand {
    /// Completes the account's configured grant into a stored token.
    pub fn execute(self, printer: &mut impl Printer, mut account: Account) -> Result<()> {
        if account.grant == GrantConfig::Device {
            if self.state.is_some() || self.pkce.is_some() || self.redirect_uri.is_some() {
                bail!(
                    "The --state, --pkce and --redirect-uri flags are only valid \
		     for the authorization-code grant"
                );
            }
            let device_code = self.input.trim();
            if device_code.is_empty() {
                bail!("Missing device code");
            }
            let Some(token_endpoint) = account.token_endpoint.clone() else {
                bail!("Missing endpoints.token in the account config");
            };
            let device = Oauth20DeviceAuthSuccessParams {
                device_code: SecretString::from(device_code),
                user_code: String::new(),
                verification_uri: String::new(),
                verification_uri_complete: None,
                expires_in: 1800,
                interval: 5,
            };
            return complete_device_token_poll(printer, &mut account, &token_endpoint, &device);
        }

        let Some(token_endpoint) = account.token_endpoint.clone() else {
            bail!("Missing endpoints.token in the account config");
        };

        // Trim like the device path: shared `input: String` is often
        // copy-pasted with surrounding whitespace. Never echo the raw
        // value: the redirect may carry `code=` / `state=` secrets.
        let input = self.input.trim();
        if input.is_empty() {
            bail!("Missing redirected URI (pass it as the positional URI|DEVICE_CODE)");
        }
        let redirected_uri =
            Url::parse(input).map_err(|err| anyhow!("Invalid redirected URI: {err}"))?;

        let code = match Oauth20AuthParams::from(&redirected_uri).validate(self.state.as_ref()) {
            Ok(code) => code,
            Err(Oauth20AuthParamsValidationError::Server(params)) => {
                let err = anyhow!("Authorization error (code {:?})", params.error);
                return Err(match (params.error_description, params.error_uri) {
                    (None, None) => err,
                    (Some(desc), None) => anyhow!("{desc}").context(err),
                    (None, Some(uri)) => anyhow!("{uri}").context(err),
                    (Some(desc), Some(uri)) => anyhow!("{desc}: {uri}").context(err),
                });
            }
            Err(Oauth20AuthParamsValidationError::StateMissing) => {
                return Err(anyhow!("Authorization response is missing state"));
            }
            Err(Oauth20AuthParamsValidationError::StateMismatch) => {
                // CSRF state must stay off error output.
                return Err(anyhow!(
                    "Authorization request and response states do not match"
                ));
            }
        };

        let client_secret = account.client_secret.clone().map(Secret::get).transpose()?;
        let redirect_uri = self
            .redirect_uri
            .as_ref()
            .map(|uri| Cow::Owned(uri.to_string()))
            .or_else(|| {
                account
                    .redirection_endpoint
                    .as_ref()
                    .map(|uri| Cow::Owned(uri.to_string()))
            });

        let pkce_verifier = match self.pkce.as_deref() {
            None => None,
            Some(raw) => Some(
                pkce_code_verifier_parser(raw)
                    .map_err(|err| anyhow!(err))?,
            ),
        };

        let mut client =
            Oauth20ClientStd::connect(token_endpoint, &account.tls, account.client_id.clone())?;
        client.client_secret = client_secret;

        let res = client.request_access_token(Oauth20AccessTokenRequestParams {
            code,
            redirect_uri,
            client_id: account.client_id.as_str().into(),
            client_secret: None,
            pkce_code_verifier: pkce_verifier.as_ref().map(Cow::Borrowed),
        })?;

        match res {
            Ok(res) => report_token_issued(printer, &mut account, &res),
            Err(res) => {
                debug!("execute issue access token error hook");
                account.execute_on_issue_error_hook(&res);
                let err = anyhow!("Issue access token error (code {:?})", res.error);
                Err(match (res.error_description, res.error_uri) {
                    (None, None) => err,
                    (Some(desc), None) => anyhow!("{desc}").context(err),
                    (None, Some(uri)) => anyhow!("{uri}").context(err),
                    (Some(desc), Some(uri)) => anyhow!("{desc}: {uri}").context(err),
                })
            }
        }
    }
}

pub fn uri_parser(url: &str) -> Result<Url, String> {
    Url::parse(url).map_err(|err| err.to_string())
}

pub fn state_parser(state: &str) -> Result<Oauth20State, String> {
    Oauth20State::deserialize(StrDeserializer::<Error>::new(state)).map_err(|e| e.to_string())
}

pub fn pkce_code_verifier_parser(verifier: &str) -> Result<Oauth20PkceCodeVerifier, String> {
    // Omit the verifier body: clap surfaces this string on stderr.
    verifier
        .parse()
        .map_err(|b| format!("Invalid 0x{b:x} found in PKCE code verifier"))
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn authorization_code_input_is_redirected_uri_string() {
        // After the device-grant String change, authorization-code
        // accounts still treat the positional as a redirected URI.
        let redirected = "  http://127.0.0.1/cb?code=abc&state=s  ";
        let cmd = AuthResumeCommand {
            input: redirected.into(),
            state: None,
            pkce: None,
            redirect_uri: None,
        };
        let trimmed = cmd.input.trim();
        assert!(!trimmed.is_empty());
        assert!(Url::parse(trimmed).is_ok());
        assert!(cmd.state.is_none());
        assert!(cmd.pkce.is_none());
        assert!(cmd.redirect_uri.is_none());
    }

    #[test]
    fn authorization_code_await_redirect_chain_fields() {
        // Mirrors auth get → AuthResumeCommand after await_redirect.
        // pkce is Option<String> so clap never re-echoes invalid values.
        let redirected = "http://127.0.0.1:9/?code=c&state=s";
        let registered: Url = "http://127.0.0.1:9/".parse().unwrap();
        let cmd = AuthResumeCommand {
            input: redirected.into(),
            state: Some(Oauth20State::default()),
            pkce: Some("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP01234".into()),
            redirect_uri: Some(registered.clone()),
        };
        assert_eq!(cmd.input, redirected);
        assert!(cmd.state.is_some());
        assert!(cmd.pkce.is_some());
        assert_eq!(cmd.redirect_uri.as_ref(), Some(&registered));
        assert!(Url::parse(&cmd.input).is_ok());
    }

    #[test]
    fn pkce_code_verifier_parser_error_omits_verifier_body() {
        let secret = "pkce-secret-value-with space";
        let err = pkce_code_verifier_parser(secret).unwrap_err();
        assert!(!err.contains(secret), "{err}");
        assert!(err.contains("Invalid 0x"), "{err}");
    }

    #[test]
    fn auth_resume_debug_redacts_positional_input() {
        let cmd = AuthResumeCommand {
            input: "device-code-super-secret".into(),
            state: None,
            pkce: None,
            redirect_uri: None,
        };
        let rendered = format!("{cmd:?}");
        assert!(!rendered.contains("device-code-super-secret"), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
    }
}
