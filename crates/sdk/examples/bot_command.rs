use contrix::BotCommandParser;

fn main() {
    let parser = BotCommandParser::new("!");
    let command = parser.parse("!echo hello").expect("command");

    assert_eq!(command.name, "echo");
    assert_eq!(command.args, vec!["hello"]);
}
