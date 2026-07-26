use zed_extension_api::{
    self as zed, serde_json::Value, settings::LspSettings, Command, Extension, LanguageServerId,
    Result, Worktree,
};

const SERVER_NAME: &str = "spice";

struct SpiceExtension;

impl Extension for SpiceExtension {
    fn new() -> Self {
        Self
    }

    fn language_server_command(
        &mut self,
        language_server_id: &LanguageServerId,
        worktree: &Worktree,
    ) -> Result<Command> {
        let settings = LspSettings::for_worktree(language_server_id.as_ref(), worktree)?;
        let configured = settings.binary.unwrap_or_else(default_binary_settings);
        let command = configured
            .path
            .or_else(|| worktree.which(SERVER_NAME))
            .ok_or_else(missing_binary_message)?;

        Ok(Command {
            command,
            args: language_server_arguments(configured.arguments),
            env: language_server_environment(configured.env),
        })
    }

    fn language_server_initialization_options(
        &mut self,
        language_server_id: &LanguageServerId,
        worktree: &Worktree,
    ) -> Result<Option<Value>> {
        Ok(
            LspSettings::for_worktree(language_server_id.as_ref(), worktree)?
                .initialization_options,
        )
    }
}

fn default_binary_settings() -> zed::settings::CommandSettings {
    zed::settings::CommandSettings {
        path: None,
        arguments: None,
        env: None,
    }
}

fn language_server_arguments(configured: Option<Vec<String>>) -> Vec<String> {
    configured.unwrap_or_else(|| vec!["lsp".to_owned()])
}

fn language_server_environment(
    configured: Option<std::collections::HashMap<String, String>>,
) -> Vec<(String, String)> {
    let mut environment = configured
        .unwrap_or_default()
        .into_iter()
        .collect::<Vec<_>>();
    environment.sort_unstable();
    environment
}

fn missing_binary_message() -> String {
    "Spice executable not found. Install `spice` on PATH or set \
     `lsp.spice.binary.path` in Zed settings. The extension never downloads \
     or executes installers."
        .to_owned()
}

zed::register_extension!(SpiceExtension);

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{language_server_arguments, language_server_environment, missing_binary_message};

    #[test]
    fn defaults_to_lsp_subcommand() {
        assert_eq!(language_server_arguments(None), vec!["lsp"]);
    }

    #[test]
    fn preserves_explicit_arguments() {
        let arguments = vec!["lsp".to_owned(), "--future-option".to_owned()];
        assert_eq!(
            language_server_arguments(Some(arguments.clone())),
            arguments
        );
    }

    #[test]
    fn orders_configured_environment() {
        let environment = HashMap::from([
            ("SPICE_SECOND".to_owned(), "2".to_owned()),
            ("SPICE_FIRST".to_owned(), "1".to_owned()),
        ]);
        assert_eq!(
            language_server_environment(Some(environment)),
            vec![
                ("SPICE_FIRST".to_owned(), "1".to_owned()),
                ("SPICE_SECOND".to_owned(), "2".to_owned()),
            ]
        );
    }

    #[test]
    fn missing_binary_error_is_actionable_and_offline_safe() {
        let message = missing_binary_message();
        assert!(message.contains("PATH"));
        assert!(message.contains("binary.path"));
        assert!(message.contains("never downloads"));
    }
}
