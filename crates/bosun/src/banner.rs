//! The startup banner, printed to stderr by `bosun serve` when stderr is a terminal.
//!
//! Colour is skipped when `NO_COLOR` is set or `TERM=dumb`. The art is in `assets/`.

use std::io::IsTerminal;

/// Print the banner if stderr is an interactive terminal; otherwise print nothing (logs and service managers
/// get the plain text lines only).
pub fn print() {
    let err = std::io::stderr();
    if !err.is_terminal() {
        return;
    }
    let colour = std::env::var_os("NO_COLOR").is_none() && std::env::var("TERM").is_ok_and(|t| t != "dumb");
    eprintln!("{}", render(colour));
}

/// The banner text, with or without ANSI colours.
pub fn render(colour: bool) -> String {
    let (orange, cyan, white, dim, reset) = if colour {
        (
            "\x1b[38;5;208m",
            "\x1b[38;5;51m",
            "\x1b[1;97m",
            "\x1b[2;37m",
            "\x1b[0m",
        )
    } else {
        ("", "", "", "", "")
    };
    format!(
        r#"{orange}         _.-._
       .'  _  '.
      /   (_)   \         {white}____   ___  ____  _   _ _   _{orange}

     |     |     |       {white}| __ ) / _ \/ ___|| | | | \ | |{orange}
  ---'-----+-----'---    {white}|  _ \| | | \___ \| | | |  \| |{orange}
      \    |    /        {white}| |_) | |_| |___) | |_| | |\  |{orange}
       '.  |  .'         {white}|____/ \___/|____/ \___/|_| \_|{orange}

    |\   \ | /   /|
    | \   \|/   / |      {dim}Fast Web Security Proxy & Scanner{orange}
     \ '-. | .-' /       {dim}[ Rust Edition ]{orange}
      '-. \|/ .-'
         '---'
         {cyan}<> <>{reset}"#
    )
}

#[cfg(test)]
mod tests {
    use super::render;

    #[test]
    fn plain_banner_has_no_escapes() {
        let s = render(false);
        assert!(!s.contains('\x1b'));
        assert!(s.contains("Fast Web Security Proxy & Scanner"));
    }

    #[test]
    fn coloured_banner_resets() {
        assert!(render(true).ends_with("\x1b[0m"));
    }
}
