fn print_banner() {
    let orange = "\x1b[38;5;208m";
    let cyan = "\x1b[38;5;51m";
    let bold_white = "\x1b[1;97m";
    let dim = "\x1b[2;37m";
    let reset = "\x1b[0m";

    println!(
        r#"{orange}         _.-._
       .'  _  '.
      /   (_)   \         {bold_white}____   ___  ____  _   _ _   _{orange}

     |     |     |       {bold_white}| __ ) / _ \/ ___|| | | | \ | |{orange}
  ---'-----+-----'---    {bold_white}|  _ \| | | \___ \| | | |  \| |{orange}
      \    |    /        {bold_white}| |_) | |_| |___) | |_| | |\  |{orange}
       '.  |  .'         {bold_white}|____/ \___/|____/ \___/|_| \_|{orange}

    |\   \ | /   /|
    | \   \|/   / |      {dim}Fast Web Security Proxy & Scanner{orange}
     \ '-. | .-' /       {dim}[ Rust Edition ]{orange}
      '-. \|/ .-'
         '---'
         {cyan}<> <>{reset}"#
    );
}


fn print_compact_header(version: &str, port: u16) {
    let orange = "\x1b[38;5;208m";
    let cyan = "\x1b[38;5;51m";
    let bold_white = "\x1b[1;97m";
    let dim = "\x1b[2;37m";
    let reset = "\x1b[0m";

    println!(
        "{orange}--(+)--{reset} {bold_white}BOSUN{reset} {cyan}<>{reset} {dim}v{version} | Proxy listening on 127.0.0.1:{port}{reset}"
    );
}
