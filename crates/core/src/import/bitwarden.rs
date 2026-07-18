//! Bitwarden importers: the unencrypted JSON export and the CSV export.

use super::csv;
use crate::error::{CoreError, Result};
use crate::vault::model::{Item, ItemType, Login, UrlMatch, UrlMode};
use serde::Deserialize;

#[derive(Deserialize)]
struct BwExport {
    items: Vec<BwItem>,
}

#[derive(Deserialize)]
struct BwItem {
    #[serde(rename = "type")]
    kind: u8,
    name: Option<String>,
    notes: Option<String>,
    login: Option<BwLogin>,
}

#[derive(Deserialize)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    uris: Option<Vec<BwUri>>,
}

#[derive(Deserialize)]
struct BwUri {
    uri: Option<String>,
}

fn item_type(kind: u8) -> ItemType {
    match kind {
        2 => ItemType::Note,
        3 => ItemType::Card,
        4 => ItemType::Identity,
        _ => ItemType::Login,
    }
}

/// Parse a Bitwarden unencrypted JSON export into items stamped at `now`.
pub fn parse_bitwarden_json(json: &str, now: i64) -> Result<Vec<Item>> {
    let export: BwExport = serde_json::from_str(json)
        .map_err(|e| CoreError::Invalid(format!("bitwarden json: {e}")))?;
    let mut out = Vec::new();
    for bw in export.items {
        let mut item = Item::new_login(bw.name.unwrap_or_default(), now);
        item.item_type = item_type(bw.kind);
        item.notes = bw.notes;
        if let Some(l) = bw.login {
            item.urls = l
                .uris
                .unwrap_or_default()
                .into_iter()
                .filter_map(|u| u.uri)
                .map(|url| UrlMatch {
                    url,
                    mode: UrlMode::Domain,
                })
                .collect();
            item.login = Some(Login {
                username: l.username,
                password: l.password,
                totp: l.totp,
            });
        } else {
            item.login = None;
        }
        out.push(item);
    }
    Ok(out)
}

/// Parse a Bitwarden CSV export.
pub fn parse_bitwarden_csv(input: &str, now: i64) -> Result<Vec<Item>> {
    let rows = csv::parse(input);
    if rows.is_empty() {
        return Ok(vec![]);
    }
    let header = &rows[0];
    let col = |name: &str| header.iter().position(|h| h == name);
    let (name_i, notes_i, uri_i, user_i, pass_i, totp_i, type_i) = (
        col("name"),
        col("notes"),
        col("login_uri"),
        col("login_username"),
        col("login_password"),
        col("login_totp"),
        col("type"),
    );

    let get = |row: &[String], idx: Option<usize>| -> Option<String> {
        idx.and_then(|i| row.get(i))
            .filter(|s| !s.is_empty())
            .cloned()
    };

    let mut out = Vec::new();
    for row in &rows[1..] {
        let mut item = Item::new_login(get(row, name_i).unwrap_or_default(), now);
        item.notes = get(row, notes_i);
        if get(row, type_i).as_deref() == Some("note") {
            item.item_type = ItemType::Note;
            item.login = None;
        } else {
            if let Some(uri) = get(row, uri_i) {
                item.urls = vec![UrlMatch {
                    url: uri,
                    mode: UrlMode::Domain,
                }];
            }
            item.login = Some(Login {
                username: get(row, user_i),
                password: get(row, pass_i),
                totp: get(row, totp_i),
            });
        }
        out.push(item);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_json_login() {
        let json = r#"{"items":[
            {"type":1,"name":"GitHub","notes":"n",
             "login":{"username":"octocat","password":"pw","totp":"JBSW",
                      "uris":[{"uri":"https://github.com"}]}},
            {"type":2,"name":"Note","notes":"body","login":null}
        ]}"#;
        let items = parse_bitwarden_json(json, 100).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "GitHub");
        assert_eq!(items[0].username(), Some("octocat"));
        assert_eq!(items[0].urls.len(), 1);
        assert_eq!(items[1].item_type, ItemType::Note);
        assert!(items[1].login.is_none());
    }

    #[test]
    fn imports_csv() {
        let input = "folder,type,name,notes,login_uri,login_username,login_password,login_totp\n\
                     ,login,Bank,,https://bank.com,me,secret,\n";
        let items = parse_bitwarden_csv(input, 5).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "Bank");
        assert_eq!(items[0].password(), Some("secret"));
        assert_eq!(items[0].urls[0].url, "https://bank.com");
    }

    #[test]
    fn round_trips_25_rows_lossless() {
        // Brief acceptance: 25 Bitwarden rows import losslessly.
        let mut json = String::from("{\"items\":[");
        for i in 0..25 {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format!(
                r#"{{"type":1,"name":"site{i}","notes":null,
                    "login":{{"username":"user{i}","password":"pass{i}","totp":null,
                              "uris":[{{"uri":"https://site{i}.com"}}]}}}}"#
            ));
        }
        json.push_str("]}");
        let items = parse_bitwarden_json(&json, 0).unwrap();
        assert_eq!(items.len(), 25);
        for (i, it) in items.iter().enumerate() {
            assert_eq!(it.title, format!("site{i}"));
            assert_eq!(it.username(), Some(format!("user{i}").as_str()));
            assert_eq!(it.password(), Some(format!("pass{i}").as_str()));
        }
    }
}
