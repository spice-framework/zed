use zed_extension_api::{
    self as zed, serde_json::Value, settings::LspSettings, CodeLabel, CodeLabelSpan, Command,
    Extension, LanguageServerId, Result, Worktree,
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

    fn label_for_completion(
        &self,
        language_server_id: &LanguageServerId,
        completion: zed::lsp::Completion,
    ) -> Option<CodeLabel> {
        if language_server_id.as_ref() != SERVER_NAME {
            return None;
        }
        let (name, detail) =
            annotation_completion_parts(&completion.label, completion.detail.as_deref())?;
        let mut spans = vec![
            CodeLabelSpan::literal("@", Some("punctuation.special".to_owned())),
            CodeLabelSpan::literal(name, Some("attribute".to_owned())),
        ];
        if let Some(detail) = detail {
            spans.push(CodeLabelSpan::literal("  ", None));
            spans.push(CodeLabelSpan::literal(detail, Some("comment".to_owned())));
        }
        Some(CodeLabel {
            code: String::new(),
            spans,
            filter_range: (0..completion.label.len()).into(),
        })
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

fn annotation_completion_parts<'a>(
    label: &'a str,
    detail: Option<&'a str>,
) -> Option<(&'a str, Option<&'a str>)> {
    let name = label.strip_prefix('@')?;
    if name.is_empty()
        || !name
            .chars()
            .all(|character| character == '.' || character == '_' || character.is_alphanumeric())
    {
        return None;
    }
    Some((name, detail.filter(|value| !value.is_empty())))
}

zed::register_extension!(SpiceExtension);

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use zed_extension_api::serde_json;

    use super::{
        annotation_completion_parts, language_server_arguments, language_server_environment,
        missing_binary_message,
    };

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

    #[test]
    fn recognizes_only_spice_annotation_completion_labels() {
        assert_eq!(
            annotation_completion_parts("@management.Enable", Some("function")),
            Some(("management.Enable", Some("function")))
        );
        assert_eq!(
            annotation_completion_parts("@Application", Some("")),
            Some(("Application", None))
        );
        assert_eq!(annotation_completion_parts("Application", None), None);
        assert_eq!(annotation_completion_parts("@invalid-name", None), None);
    }

    #[test]
    fn projected_workspace_task_template_is_bounded_and_exact() {
        let tasks: serde_json::Value =
            serde_json::from_str(include_str!("../docs/spice-tasks.json")).unwrap();
        let tasks = tasks.as_array().unwrap();
        assert_eq!(tasks.len(), 5);
        let labels = tasks
            .iter()
            .map(|task| task["label"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            labels,
            vec![
                "Spice: Open Projected Shell",
                "Spice: Open Codex in View",
                "Spice: Build",
                "Spice: Test",
                "Spice: Verify",
            ]
        );
        assert_eq!(tasks[0]["args"], serde_json::json!(["shell", "--retain"]));
        assert_eq!(
            tasks[1]["args"],
            serde_json::json!(["shell", "--retain", "--", "codex"])
        );
        for task in tasks {
            assert_eq!(task["command"], "spice");
            assert_eq!(task["cwd"], "$ZED_WORKTREE_ROOT");
            assert_eq!(task["allow_concurrent_runs"], false);
        }
    }
}
