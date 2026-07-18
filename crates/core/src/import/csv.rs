//! A minimal RFC-4180-ish CSV parser: quoted fields, escaped quotes (`""`), and
//! embedded newlines/commas. Enough for password-manager exports without a crate.

/// Parse CSV into rows of string fields. Handles quoting and embedded newlines.
pub fn parse(input: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut field = String::new();
    let mut record: Vec<String> = Vec::new();
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            match c {
                '"' => {
                    if chars.peek() == Some(&'"') {
                        field.push('"');
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                }
                _ => field.push(c),
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => {
                    record.push(std::mem::take(&mut field));
                }
                '\r' => {}
                '\n' => {
                    record.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut record));
                }
                _ => field.push(c),
            }
        }
    }
    // Trailing field/record if the file didn't end with a newline.
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        rows.push(record);
    }
    rows.retain(|r| !(r.len() == 1 && r[0].is_empty()));
    rows
}

/// Serialize rows to CSV, quoting fields that need it.
pub fn write(rows: &[Vec<String>]) -> String {
    let mut out = String::new();
    for row in rows {
        let line: Vec<String> = row.iter().map(|f| quote(f)).collect();
        out.push_str(&line.join(","));
        out.push('\n');
    }
    out
}

fn quote(f: &str) -> String {
    if f.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", f.replace('"', "\"\""))
    } else {
        f.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quoted_and_embedded() {
        let input = "a,b,c\n\"quoted, comma\",\"line\nbreak\",\"esc\"\"aped\"\n";
        let rows = parse(input);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], vec!["a", "b", "c"]);
        assert_eq!(rows[1][0], "quoted, comma");
        assert_eq!(rows[1][1], "line\nbreak");
        assert_eq!(rows[1][2], "esc\"aped");
    }

    #[test]
    fn round_trip() {
        let rows = vec![
            vec!["name".to_string(), "url".to_string()],
            vec!["has,comma".to_string(), "plain".to_string()],
        ];
        let s = write(&rows);
        let back = parse(&s);
        assert_eq!(rows, back);
    }
}
