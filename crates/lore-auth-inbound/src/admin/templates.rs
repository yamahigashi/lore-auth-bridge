//! Askama template bindings for the admin UI.
//! Template files remain under the crate-level templates directory.

use askama::Template;

use super::groups::GroupRow;
use super::i18n::translate;
use super::repositories::RepositoryRow;
use super::simulator::SimulatorResultView;
use super::users::{AccessRow, UserRow};

#[derive(Template)]
#[template(path = "admin/dashboard.html")]
pub(super) struct DashboardTemplate<'a> {
    pub(super) active: &'a str,
    pub(super) lang: &'a str,
    pub(super) user_email: &'a str,
    pub(super) user_display: &'a str,
    pub(super) flash: &'a str,
}

impl DashboardTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(self.lang, key)
    }
}

#[derive(Template)]
#[template(path = "admin/repositories.html")]
pub(super) struct RepositoriesTemplate<'a> {
    pub(super) active: &'a str,
    pub(super) lang: &'a str,
    pub(super) query: &'a str,
    pub(super) rows: &'a [RepositoryRow],
    pub(super) limit: usize,
    pub(super) csrf_token: &'a str,
    pub(super) flash: &'a str,
}

impl RepositoriesTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(self.lang, key)
    }
}

#[derive(Template)]
#[template(path = "admin/repositories_table.html")]
pub(super) struct RepositoriesTableTemplate<'a> {
    pub(super) lang: &'a str,
    pub(super) rows: &'a [RepositoryRow],
    pub(super) limit: usize,
    pub(super) csrf_token: &'a str,
}

impl RepositoriesTableTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(self.lang, key)
    }
}

#[derive(Template)]
#[template(path = "admin/users.html")]
pub(super) struct UsersTemplate<'a> {
    pub(super) active: &'a str,
    pub(super) lang: &'a str,
    pub(super) query: &'a str,
    pub(super) rows: &'a [UserRow],
    pub(super) limit: usize,
    pub(super) csrf_token: &'a str,
    pub(super) flash: &'a str,
    pub(super) current_user_id: &'a str,
}

impl UsersTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(self.lang, key)
    }
}

#[derive(Template)]
#[template(path = "admin/users_table.html")]
pub(super) struct UsersTableTemplate<'a> {
    pub(super) lang: &'a str,
    pub(super) rows: &'a [UserRow],
    pub(super) limit: usize,
    pub(super) csrf_token: &'a str,
    pub(super) current_user_id: &'a str,
}

impl UsersTableTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(self.lang, key)
    }
}

#[derive(Template)]
#[template(path = "admin/user_access.html")]
pub(super) struct UserAccessTemplate<'a> {
    pub(super) active: &'a str,
    pub(super) lang: &'a str,
    pub(super) user: UserRow,
    pub(super) rows: Vec<AccessRow>,
    pub(super) limit: usize,
    pub(super) flash: &'a str,
}

impl UserAccessTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(self.lang, key)
    }
}

#[derive(Template)]
#[template(path = "admin/groups.html")]
pub(super) struct GroupsTemplate<'a> {
    pub(super) active: &'a str,
    pub(super) lang: &'a str,
    pub(super) query: &'a str,
    pub(super) rows: Vec<GroupRow>,
    pub(super) limit: usize,
    pub(super) csrf_token: &'a str,
    pub(super) flash: &'a str,
}

impl GroupsTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(self.lang, key)
    }
}

#[derive(Template)]
#[template(path = "admin/simulator.html")]
pub(super) struct SimulatorTemplate<'a> {
    pub(super) active: &'a str,
    pub(super) lang: &'a str,
    pub(super) csrf_token: &'a str,
    pub(super) input_user: &'a str,
    pub(super) input_resource: &'a str,
    pub(super) input_action: &'a str,
    pub(super) result: SimulatorResultView,
    pub(super) flash: &'a str,
}

impl SimulatorTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(self.lang, key)
    }
}
