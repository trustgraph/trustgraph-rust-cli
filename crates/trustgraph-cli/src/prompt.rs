//! Interactive prompts for `trust rate`, shown on stderr so that stdout
//! stays JSON. Used only when both stdin and stderr are terminals.

use std::io::{self, IsTerminal};

use anyhow::Result;
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Input};
use trustgraph_core::Value;

use crate::cli::parse_value;
use crate::contacts::Contacts;

/// Whether we can ask the user questions.
pub fn interactive() -> bool {
    io::stdin().is_terminal() && io::stderr().is_terminal()
}

/// Checks a target as typed: an identifier or a known `@contact`.
pub fn check_target(input: &str, contacts: &Contacts) -> Result<(), String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("enter a DID, URL, @contact, or other identifier".into());
    }
    if input.chars().any(char::is_whitespace) {
        return Err("identifiers cannot contain spaces".into());
    }
    contacts.resolve(input).map(drop).map_err(|e| e.to_string())
}

/// Checks a value as typed: `-1..=1`, or `RATING/BEST` such as `4/5`.
pub fn check_value(input: &str) -> Result<Value, String> {
    parse_value(input.trim()).map_err(|e| format!("{e} (enter -1 to 1, or a rating such as 4/5)"))
}

/// Asks who or what to rate.
pub fn target(contacts: &Contacts) -> Result<String> {
    let names: Vec<String> = contacts.iter().map(|(name, _)| format!("@{name}")).collect();
    let prompt = if names.is_empty() {
        "Who or what are you rating? (DID, URL, …)".to_owned()
    } else {
        format!("Who or what are you rating? (DID, URL, or {})", names.join(", "))
    };
    let answer: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .validate_with(|s: &String| check_target(s, contacts))
        .interact_text()?;
    Ok(answer.trim().to_owned())
}

/// Asks what the rating is about (optional).
pub fn content() -> Result<Option<String>> {
    let answer: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("What about? (a topic or comma-separated tags; empty for none)")
        .allow_empty(true)
        .interact_text()?;
    let answer = answer.trim();
    Ok((!answer.is_empty()).then(|| answer.to_owned()))
}

/// Asks how much to trust.
pub fn value() -> Result<Value> {
    let answer: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("How much do you trust it? (-1 distrust … 0 neutral … 1 full trust, or e.g. 4/5)")
        .validate_with(|s: &String| check_value(s).map(drop))
        .interact_text()?;
    check_value(&answer).map_err(anyhow::Error::msg)
}

/// Asks for confirmation.
pub fn confirm(question: &str) -> Result<bool> {
    Ok(Confirm::with_theme(&ColorfulTheme::default()).with_prompt(question).default(true).interact()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_are_checked() {
        let contacts = Contacts::default();
        assert!(check_target(" did:key:z6Mk ", &contacts).is_ok());
        assert!(check_target("", &contacts).is_err());
        assert!(check_target("a b", &contacts).is_err());
        assert!(check_target("@nobody", &contacts).unwrap_err().contains("no contact"));
        assert_eq!(check_value(" 4/5 ").unwrap().to_string(), "0.8");
        assert!(check_value("2").unwrap_err().contains("4/5"));
    }
}
