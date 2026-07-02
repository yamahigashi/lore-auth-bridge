use lore_auth_core::model::Permission;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PermissionSet {
    read: bool,
    write: bool,
    admin: bool,
}

impl PermissionSet {
    pub(crate) fn insert(&mut self, permission: Permission) {
        match permission {
            Permission::Read => self.read = true,
            Permission::Write => self.write = true,
            Permission::Admin => self.admin = true,
        }
    }

    pub(crate) fn into_permissions(self) -> Vec<Permission> {
        let mut out = Vec::new();
        if self.read {
            out.push(Permission::Read);
        }
        if self.write {
            out.push(Permission::Write);
        }
        if self.admin {
            out.push(Permission::Admin);
        }
        out
    }
}
