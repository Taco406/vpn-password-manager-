//! Chrome / Chromium password CSV importer. Header: name,url,username,password,note.

use super::csv;
use crate::error::Result;
use crate::vault::model::{Item, Login, UrlMatch, UrlMode};

/// Parse a Chrome password CSV export into items stamped at `now`.
pub fn parse_chrome_csv(input: &str, now: i64) -> Result<Vec<Item>> {
    let rows = csv::parse(input);
    if rows.is_empty() {
        return Ok(vec![]);
    }
    let header = &rows[0];
    let col = |name: &str| header.iter().position(|h| h.eq_ignore_ascii_case(name));
    let (name_i, url_i, user_i, pass_i, note_i) = (
        col("name"),
        col("url"),
        col("username"),
        col("password"),
        col("note"),
    );
    let get = |row: &[String], idx: Option<usize>| -> Option<String> {
        idx.and_then(|i| row.get(i))
            .filter(|s| !s.is_empty())
            .cloned()
    };

    let mut out = Vec::new();
    for row in &rows[1..] {
        let title = get(row, name_i)
            .or_else(|| get(row, url_i))
            .unwrap_or_default();
        let mut item = Item::new_login(title, now);
        item.notes = get(row, note_i);
        if let Some(url) = get(row, url_i) {
            item.urls = vec![UrlMatch {
                url,
                mode: UrlMode::Domain,
            }];
        }
        item.login = Some(Login {
            username: get(row, user_i),
            password: get(row, pass_i),
            totp: None,
        });
        out.push(item);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_chrome_csv() {
        let input = "name,url,username,password,note\n\
                     github.com,https://github.com/login,octocat,pw,\n\
                     Bank,https://bank.example,me,s3cret,my bank\n";
        let items = parse_chrome_csv(input, 10).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "github.com");
        assert_eq!(items[0].username(), Some("octocat"));
        assert_eq!(items[1].notes.as_deref(), Some("my bank"));
        assert_eq!(items[1].password(), Some("s3cret"));
    }
}
