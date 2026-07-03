//! Admin UI translation dictionaries and language-cookie handling.
//! Integrity checks keep template translation keys aligned with YAML dictionaries.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::LazyLock,
};

use axum::http::{HeaderMap, header};

const ADMIN_LANG_COOKIE: &str = "admin_lang";
const DEFAULT_LANG: &str = "en";
const EN_DICT_RAW: &str = include_str!("i18n/en.yaml");
const JA_DICT_RAW: &str = include_str!("i18n/ja.yaml");
const BASE_TEMPLATE_RAW: &str = include_str!("../../templates/admin/base.html");
const DASHBOARD_TEMPLATE_RAW: &str = include_str!("../../templates/admin/dashboard.html");
const REPOSITORIES_TEMPLATE_RAW: &str = include_str!("../../templates/admin/repositories.html");
const REPOSITORIES_TABLE_TEMPLATE_RAW: &str =
    include_str!("../../templates/admin/repositories_table.html");
const USERS_TEMPLATE_RAW: &str = include_str!("../../templates/admin/users.html");
const USERS_TABLE_TEMPLATE_RAW: &str = include_str!("../../templates/admin/users_table.html");
const USER_ACCESS_TEMPLATE_RAW: &str = include_str!("../../templates/admin/user_access.html");
const GROUPS_TEMPLATE_RAW: &str = include_str!("../../templates/admin/groups.html");
const SIMULATOR_TEMPLATE_RAW: &str = include_str!("../../templates/admin/simulator.html");

static EN_DICT: LazyLock<BTreeMap<String, String>> =
    LazyLock::new(|| load_dictionary("en", EN_DICT_RAW));
static JA_DICT: LazyLock<BTreeMap<String, String>> =
    LazyLock::new(|| load_dictionary("ja", JA_DICT_RAW));

pub(super) fn translate(lang: &str, key: &str) -> String {
    dictionary(lang)
        .get(key)
        .cloned()
        .unwrap_or_else(|| key.to_owned())
}

pub(super) fn resolve_lang(headers: &HeaderMap, query_lang: Option<&str>) -> String {
    if let Some(lang) = query_lang.filter(|lang| is_supported_lang(lang)) {
        return lang.to_owned();
    }
    if let Some(lang) =
        cookie_value(headers, ADMIN_LANG_COOKIE).filter(|lang| is_supported_lang(lang))
    {
        return lang;
    }
    DEFAULT_LANG.to_owned()
}

pub(super) fn is_supported_lang(value: &str) -> bool {
    matches!(value, "en" | "ja")
}

fn dictionary(lang: &str) -> &'static BTreeMap<String, String> {
    match lang {
        "ja" => &JA_DICT,
        _ => &EN_DICT,
    }
}

fn load_dictionary(lang: &str, raw: &str) -> BTreeMap<String, String> {
    serde_yaml_ng::from_str(raw).unwrap_or_else(|err| panic!("admin {lang} i18n failed: {err}"))
}

pub fn assert_i18n_integrity() {
    let en_keys = EN_DICT.keys().cloned().collect::<BTreeSet<_>>();
    let ja_keys = JA_DICT.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(en_keys, ja_keys, "admin en/ja i18n keys differ");
    let template_keys = template_i18n_keys();
    assert!(
        !template_keys.is_empty(),
        "admin templates must reference i18n keys"
    );
    for key in template_keys {
        assert!(en_keys.contains(&key), "missing admin i18n key {key:?}");
    }
}

fn template_i18n_keys() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for source in [
        BASE_TEMPLATE_RAW,
        DASHBOARD_TEMPLATE_RAW,
        REPOSITORIES_TEMPLATE_RAW,
        REPOSITORIES_TABLE_TEMPLATE_RAW,
        USERS_TEMPLATE_RAW,
        USERS_TABLE_TEMPLATE_RAW,
        USER_ACCESS_TEMPLATE_RAW,
        GROUPS_TEMPLATE_RAW,
        SIMULATOR_TEMPLATE_RAW,
    ] {
        let mut rest = source;
        while let Some((_, tail)) = rest.split_once("t(\"") {
            if let Some((key, after)) = tail.split_once("\")") {
                out.insert(key.to_owned());
                rest = after;
            } else {
                break;
            }
        }
    }
    out
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let (key, value) = part.trim().split_once('=')?;
        if key == name {
            return Some(value.to_owned());
        }
    }
    None
}

pub(super) fn lang_cookie(value: &str, secure: bool) -> String {
    let mut cookie = format!(
        "{ADMIN_LANG_COOKIE}={value}; Path=/admin; Max-Age=31536000; HttpOnly; SameSite=Lax"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}
