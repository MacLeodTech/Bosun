//! Spawning child processes (the launched browser, later crawler browsers and plugins) with a clean environment.
//!
//! A child that loads hostile content must not inherit Bosun's secrets (`BOSUN_DATA_KEY` unseals the CA key), so
//! every child starts from an empty environment plus a short allowlist of what a desktop program needs to run.

use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::Command;

/// Variables passed through by exact name. Compared case-insensitively (Windows environment names are).
const ALLOW: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "PROGRAMDATA",
    "TEMP",
    "TMP",
    "TMPDIR",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "DBUS_SESSION_BUS_ADDRESS",
    "LANG",
    "SYSTEMROOT",
    "WINDIR",
];

/// Variables passed through by prefix.
const ALLOW_PREFIX: &[&str] = &["XDG_", "LC_"];

/// Names that are never passed, even if an allowlist entry would match.
const DENY_PREFIX: &[&str] = &["BOSUN_"];

fn allowed(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let up = name.to_ascii_uppercase();
    if DENY_PREFIX.iter().any(|p| up.starts_with(p)) {
        return false;
    }
    ALLOW.contains(&up.as_str()) || ALLOW_PREFIX.iter().any(|p| up.starts_with(p))
}

/// The subset of `vars` a child may inherit.
pub fn filter_env<I>(vars: I) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    vars.into_iter().filter(|(k, _)| allowed(k)).collect()
}

/// A command for `program` that starts from an empty environment plus the allowlisted variables of ours.
pub fn clean_command(program: &Path) -> Command {
    let mut cmd = Command::new(program);
    cmd.env_clear().envs(filter_env(std::env::vars_os()));
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(v: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        v.iter().map(|(k, v)| (k.into(), v.into())).collect()
    }

    #[test]
    fn secrets_never_pass_and_allowlisted_variables_survive() {
        let out = filter_env(pairs(&[
            ("BOSUN_DATA_KEY", "secret"),
            ("BOSUN_DATA_KEY_FILE", "/run/secrets/k"),
            ("bosun_data_key", "secret"),
            ("AWS_SECRET_ACCESS_KEY", "x"),
            ("PATH", "/usr/bin"),
            ("HOME", "/home/u"),
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ("LC_ALL", "C"),
            ("DISPLAY", ":0"),
            ("SystemRoot", "C:\\Windows"),
        ]));
        let names: Vec<_> = out.iter().map(|(k, _)| k.to_str().unwrap()).collect();
        assert_eq!(
            names,
            [
                "PATH",
                "HOME",
                "XDG_RUNTIME_DIR",
                "LC_ALL",
                "DISPLAY",
                "SystemRoot"
            ]
        );
    }

    #[test]
    fn the_spawned_command_has_a_cleared_environment() {
        let cmd = clean_command(Path::new("true"));
        let envs: Vec<_> = cmd.get_envs().collect();
        assert!(envs.iter().all(|(k, _)| allowed(k)));
        assert!(
            !envs
                .iter()
                .any(|(k, _)| k.to_string_lossy().starts_with("BOSUN_"))
        );
    }
}
