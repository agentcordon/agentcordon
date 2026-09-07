//! Writing the skill, and the one pointer file a runtime without skill
//! discovery needs.
//!
//! Every path here is relative to the workspace root, every write is
//! idempotent, and nothing outside a `<!-- BEGIN AGENTCORDON -->` /
//! `<!-- END AGENTCORDON -->` (or `# BEGIN AGENTCORDON` / `# END AGENTCORDON`)
//! pair is ever touched. A skill file is different: `init` owns the whole file,
//! so it is written entire and has no markers.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::CliError;

use super::{Runtime, Writer, PORTABLE_SKILL_DIR, SKILL_MD, SKILL_NAME};

/// What happened to one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Created,
    Updated,
    /// Already exactly right; nothing written.
    Unchanged,
    /// Deliberately not written. Carries the reason and the snippet to add by
    /// hand.
    Skipped {
        reason: String,
        snippet: String,
    },
}

/// One line of the summary `init` prints.
#[derive(Debug, Clone)]
pub struct Installed {
    /// Workspace-relative path, in `/`-separated form.
    pub path: String,
    pub action: Action,
    /// Display names of the selected runtimes this file serves.
    pub serves: Vec<&'static str>,
    /// Anything the verb does not say — that a merge re-serialised the file,
    /// say. Printed under the path.
    pub detail: Option<String>,
}

/// The line `.aider.conf.yml` needs, and the file it points at.
pub const AIDER_CONF: &str = ".aider.conf.yml";
const AIDER_BEGIN: &str = "# BEGIN AGENTCORDON";
const AIDER_END: &str = "# END AGENTCORDON";

/// The `read:` block written into `.aider.conf.yml`.
pub fn aider_block() -> String {
    format!(
        "{AIDER_BEGIN}\n\
         # Aider loads no instruction file on its own; this names the AgentCordon skill.\n\
         read:\n  \
         - {PORTABLE_SKILL_DIR}/{SKILL_NAME}/SKILL.md\n\
         {AIDER_END}\n"
    )
}

/// Install the skill and every selected runtime's extra file into `root`.
///
/// [`PORTABLE_SKILL_DIR`] is always written, whatever is selected: it is the
/// open-standard path that thirteen of the fifteen runtimes read, it is what
/// Aider's `read:` entry names, and it is what a runtime nobody selected will
/// find if this workspace is opened in it later.
pub fn install(root: &Path, selected: &[&'static Runtime]) -> Result<Vec<Installed>, CliError> {
    let mut out = Vec::new();

    let portable_serves: Vec<&'static str> = selected
        .iter()
        .filter(|r| r.reads.starts_with(PORTABLE_SKILL_DIR))
        .map(|r| r.display)
        .collect();
    out.push(write_skill(root, PORTABLE_SKILL_DIR, portable_serves)?);

    // A skill root may be shared (Claude Code and Cline both read
    // `.claude/skills`), so collect the runtimes per root before writing.
    let mut copies: Vec<(&'static str, Vec<&'static str>)> = Vec::new();
    let mut aider_for: Vec<&'static str> = Vec::new();
    for runtime in selected {
        for writer in runtime.writers {
            match writer {
                Writer::SkillCopy(dir) => match copies.iter_mut().find(|(d, _)| d == dir) {
                    Some((_, names)) => names.push(runtime.display),
                    None => copies.push((dir, vec![runtime.display])),
                },
                Writer::AiderRead => aider_for.push(runtime.display),
            }
        }
    }

    for (dir, serves) in copies {
        out.push(write_skill(root, dir, serves)?);
    }
    if !aider_for.is_empty() {
        out.push(write_aider_conf(root, aider_for)?);
    }

    Ok(out)
}

/// Write the skill into `<root>/<skill_root>/agentcordon/SKILL.md`.
///
/// `init` owns the whole file, so it is compared byte-for-byte and rewritten
/// when it differs. There are no markers: a skill file with a user's prose in
/// it is a different skill, and the Agent Skills spec gives the file one
/// `name`, which is ours.
fn write_skill(
    root: &Path,
    skill_root: &str,
    serves: Vec<&'static str>,
) -> Result<Installed, CliError> {
    let dir = join_rel(root, skill_root).join(SKILL_NAME);
    let path = dir.join("SKILL.md");
    let rel = format!("{skill_root}/{SKILL_NAME}/SKILL.md");

    let existing = fs::read_to_string(&path).ok();
    let action = match existing {
        Some(ref c) if c == SKILL_MD => Action::Unchanged,
        Some(_) => Action::Updated,
        None => Action::Created,
    };

    if action != Action::Unchanged {
        fs::create_dir_all(&dir)
            .map_err(|e| CliError::general(format!("failed to create {skill_root}/: {e}")))?;
        fs::write(&path, SKILL_MD)
            .map_err(|e| CliError::general(format!("failed to write {rel}: {e}")))?;
    }

    Ok(Installed {
        path: rel,
        action,
        serves,
        detail: None,
    })
}

/// Add `read:` to `.aider.conf.yml`, or print the snippet when the file
/// already has one.
///
/// Aider merges a `read:` key from the config file with `--read` on the
/// command line, but a YAML mapping may only carry one `read` key: appending a
/// second silently loses one of them, depending on the parser. So a file that
/// already has `read:` is left byte-identical and the two lines are printed for
/// the user to merge.
fn write_aider_conf(root: &Path, serves: Vec<&'static str>) -> Result<Installed, CliError> {
    let path = join_rel(root, AIDER_CONF);
    let block = aider_block();

    let Ok(content) = fs::read_to_string(&path) else {
        fs::write(&path, &block)
            .map_err(|e| CliError::general(format!("failed to write {AIDER_CONF}: {e}")))?;
        return Ok(Installed {
            path: AIDER_CONF.into(),
            action: Action::Created,
            serves,
            detail: None,
        });
    };

    if let (Some(start), Some(end)) = (content.find(AIDER_BEGIN), content.find(AIDER_END)) {
        let end = end + AIDER_END.len();
        let end = if content[end..].starts_with('\n') {
            end + 1
        } else {
            end
        };
        let updated = format!("{}{}{}", &content[..start], block, &content[end..]);
        let action = if updated == content {
            Action::Unchanged
        } else {
            fs::write(&path, &updated)
                .map_err(|e| CliError::general(format!("failed to write {AIDER_CONF}: {e}")))?;
            Action::Updated
        };
        return Ok(Installed {
            path: AIDER_CONF.into(),
            action,
            serves,
            detail: None,
        });
    }

    if has_read_key(&content) {
        return Ok(Installed {
            path: AIDER_CONF.into(),
            action: Action::Skipped {
                reason: format!(
                    "{AIDER_CONF} already has a `read:` key; a YAML mapping may only have one, \
                     so nothing was changed. Add this under it:"
                ),
                snippet: format!("- {PORTABLE_SKILL_DIR}/{SKILL_NAME}/SKILL.md"),
            },
            serves,
            detail: None,
        });
    }

    let separator = if content.ends_with('\n') || content.is_empty() {
        ""
    } else {
        "\n"
    };
    fs::write(&path, format!("{content}{separator}{block}"))
        .map_err(|e| CliError::general(format!("failed to update {AIDER_CONF}: {e}")))?;
    Ok(Installed {
        path: AIDER_CONF.into(),
        action: Action::Updated,
        serves,
        detail: None,
    })
}

/// A top-level `read:` key, ignoring comments and nested keys.
fn has_read_key(yaml: &str) -> bool {
    yaml.lines().any(|line| {
        let t = line.trim_end();
        !t.starts_with('#')
            && !t.starts_with(char::is_whitespace)
            && (t.trim_end() == "read:" || t.starts_with("read:"))
    })
}

/// Join a `/`-separated workspace-relative path onto `root`.
pub(crate) fn join_rel(root: &Path, rel: &str) -> PathBuf {
    let mut p = root.to_path_buf();
    for segment in rel.split('/') {
        p.push(segment);
    }
    p
}
