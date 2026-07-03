//! Audited memory store wrappers and admin-write audit recording.
//! Keeps mutating admin ports behavior aligned with the base in-memory store.

use std::sync::Arc;

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{
        AddInvitationInput, AddUserInput, Grant, GrantEvidence, Group, IdentityInvitation,
        LoginBindingResult, LoginResolutionRequest, Resource, TokenPrincipal, User, UserListFilter,
    },
    ports::{
        AccountDirectory, AccountQuery, AdminWritePortFactory, AdminWritePorts, GrantAdmin,
        GrantQuery, GroupAdmin, GroupQuery, ResourceQuery, ResourceStore,
    },
};

use super::{
    Store, admin_audit_entry, grant_detail, group_group_would_cycle, normalize_resource_for_upsert,
    resolve_grant_subject_id, resolve_group_id, resolve_resource_id_for_repo, resolve_user_id,
    validated_account_email,
};

#[derive(Clone, Debug)]
pub struct AuditedStore {
    pub(super) inner: Store,
    pub(super) actor: String,
}

impl AuditedStore {
    pub(super) fn new(inner: Store, actor: String) -> Self {
        Self { inner, actor }
    }
}

#[derive(Clone, Debug)]
pub struct AuditedStoreFactory {
    store: Store,
}

impl AuditedStoreFactory {
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self { store }
    }
}

impl AdminWritePortFactory for AuditedStoreFactory {
    fn for_actor(&self, actor: &str) -> AdminWritePorts {
        let audited = Arc::new(self.store.audited(actor.to_owned()));
        AdminWritePorts {
            accounts: audited.clone(),
            resources: audited.clone(),
            groups: audited.clone(),
            grants: audited,
        }
    }
}

#[async_trait]
impl GroupAdmin for AuditedStore {
    async fn add_group(&self, name: &str, description: &str) -> Result<Group, CoreError> {
        if name.trim().is_empty() {
            return Err(CoreError::InvalidArgument(
                "group name must not be empty".to_owned(),
            ));
        }
        let group = Group {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.trim().to_owned(),
            description: description.to_owned(),
        };
        let mut state = self.inner.lock();
        state.groups.insert(group.name.clone(), group.clone());
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "group.add",
            "group",
            group.id.clone(),
            format!("name={}", group.name),
        ));
        Ok(group)
    }

    async fn add_group_member(&self, group: &str, user_email_or_id: &str) -> Result<(), CoreError> {
        let mut state = self.inner.lock();
        let user_id = resolve_user_id(&state, user_email_or_id)?.to_owned();
        state
            .group_members
            .entry(user_id)
            .or_default()
            .push(group.to_owned());
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "group.member.add",
            "group",
            group,
            format!("user={user_email_or_id}"),
        ));
        Ok(())
    }

    async fn remove_group_member(
        &self,
        group: &str,
        user_email_or_id: &str,
    ) -> Result<(), CoreError> {
        let mut state = self.inner.lock();
        let user_id = resolve_user_id(&state, user_email_or_id)?.to_owned();
        if let Some(groups) = state.group_members.get_mut(&user_id) {
            groups.retain(|name| name != group);
        }
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "group.member.remove",
            "group",
            group,
            format!("user={user_email_or_id}"),
        ));
        Ok(())
    }

    async fn add_group_group(
        &self,
        parent_group: &str,
        member_group: &str,
    ) -> Result<(), CoreError> {
        let mut state = self.inner.lock();
        let parent_group_id = resolve_group_id(&state, parent_group)?.to_owned();
        let member_group_id = resolve_group_id(&state, member_group)?.to_owned();
        if parent_group_id == member_group_id {
            return Err(CoreError::InvalidArgument(
                "group cannot contain itself".to_owned(),
            ));
        }
        if state
            .group_groups
            .get(&parent_group_id)
            .is_some_and(|members| members.contains(&member_group_id))
        {
            return Ok(());
        }
        if group_group_would_cycle(&state, &parent_group_id, &member_group_id) {
            return Err(CoreError::InvalidArgument(
                "group nesting would create a cycle".to_owned(),
            ));
        }
        state
            .group_groups
            .entry(parent_group_id)
            .or_default()
            .push(member_group_id);
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "group.nest.add",
            "group",
            parent_group,
            format!("member_group={member_group}"),
        ));
        Ok(())
    }

    async fn remove_group_group(
        &self,
        parent_group: &str,
        member_group: &str,
    ) -> Result<(), CoreError> {
        let mut state = self.inner.lock();
        let parent_group_id = resolve_group_id(&state, parent_group)?.to_owned();
        let member_group_id = resolve_group_id(&state, member_group)?.to_owned();
        let members = state
            .group_groups
            .get_mut(&parent_group_id)
            .ok_or(CoreError::NotFound)?;
        let Some(index) = members.iter().position(|id| id == &member_group_id) else {
            return Err(CoreError::NotFound);
        };
        members.remove(index);
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "group.nest.remove",
            "group",
            parent_group,
            format!("member_group={member_group}"),
        ));
        Ok(())
    }
}

#[async_trait]
impl GroupQuery for AuditedStore {
    async fn list_groups(&self) -> Result<Vec<Group>, CoreError> {
        self.inner.list_groups().await
    }

    async fn list_group_members(&self, group: &str) -> Result<Vec<User>, CoreError> {
        self.inner.list_group_members(group).await
    }

    async fn list_group_groups(&self, group: &str) -> Result<Vec<Group>, CoreError> {
        self.inner.list_group_groups(group).await
    }
}

#[async_trait]
impl GrantAdmin for AuditedStore {
    async fn add_grant(
        &self,
        subject_type: &str,
        subject_id: &str,
        repo: &str,
        role: &str,
    ) -> Result<Grant, CoreError> {
        if !lore_auth_core::model::is_known_role(role) {
            return Err(CoreError::InvalidArgument(format!(
                "unknown grant role {role:?}"
            )));
        }
        let grant = Grant {
            id: uuid::Uuid::new_v4().to_string(),
            subject_type: subject_type.to_owned(),
            subject_id: String::new(),
            repository_id: repo.to_owned(),
            role: role.to_owned(),
        };
        let mut state = self.inner.lock();
        let subject_id = resolve_grant_subject_id(&state, subject_type, subject_id)?;
        let resource_id = resolve_resource_id_for_repo(&state, repo)?;
        let grant = Grant {
            subject_id: subject_id.clone(),
            ..grant
        };
        state
            .grants
            .entry((subject_type.to_owned(), subject_id.clone()))
            .or_default()
            .insert(resource_id, role.to_owned());
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "grant.add",
            "grant",
            grant.id.clone(),
            grant_detail(subject_type, &subject_id, repo, role),
        ));
        Ok(grant)
    }

    async fn remove_grant(
        &self,
        subject_type: &str,
        subject_id: &str,
        repo: &str,
        role: &str,
    ) -> Result<(), CoreError> {
        let mut state = self.inner.lock();
        let subject_id = resolve_grant_subject_id(&state, subject_type, subject_id)?;
        let resource_id = resolve_resource_id_for_repo(&state, repo)?;
        if let Some(resources) = state
            .grants
            .get_mut(&(subject_type.to_owned(), subject_id.clone()))
        {
            resources.remove(&resource_id);
        }
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "grant.remove",
            "grant",
            format!("{subject_type}:{subject_id}:{repo}:{role}"),
            grant_detail(subject_type, &subject_id, repo, role),
        ));
        Ok(())
    }
}

#[async_trait]
impl GrantQuery for AuditedStore {
    async fn list_grants(&self, repo: &str) -> Result<Vec<Grant>, CoreError> {
        self.inner.list_grants(repo).await
    }

    async fn grants_for_user_on_repository(
        &self,
        user_id: &str,
        resource_id: &str,
        include_nested_groups: bool,
    ) -> Result<Vec<GrantEvidence>, CoreError> {
        self.inner
            .grants_for_user_on_repository(user_id, resource_id, include_nested_groups)
            .await
    }
}

#[async_trait]
impl AccountDirectory for AuditedStore {
    async fn resolve_login(
        &self,
        req: LoginResolutionRequest,
    ) -> Result<(TokenPrincipal, LoginBindingResult), CoreError> {
        self.inner.resolve_login(req).await
    }

    async fn principal_by_user_id(&self, user_id: &str) -> Result<TokenPrincipal, CoreError> {
        self.inner.principal_by_user_id(user_id).await
    }

    async fn principal_by_authn_token_jti(&self, jti: &str) -> Result<TokenPrincipal, CoreError> {
        self.inner.principal_by_authn_token_jti(jti).await
    }

    async fn add_user(&self, input: AddUserInput) -> Result<User, CoreError> {
        let email = validated_account_email(&input.email)?;
        let user = User {
            id: uuid::Uuid::new_v4().to_string(),
            email,
            display_name: input.display_name,
            status: "active".to_owned(),
            last_login_at: 0,
        };
        let mut state = self.inner.lock();
        state.users.insert(user.id.clone(), user.clone());
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "user.add",
            "user",
            user.id.clone(),
            format!("email={}", user.email),
        ));
        Ok(user)
    }

    async fn add_invitation(
        &self,
        input: AddInvitationInput,
    ) -> Result<(User, IdentityInvitation), CoreError> {
        if input.provider_id.trim().is_empty() || input.issuer.trim().is_empty() {
            return Err(CoreError::InvalidArgument(
                "provider_id, issuer, and email are required".to_owned(),
            ));
        }
        let email = validated_account_email(&input.email)?;
        let user = User {
            id: uuid::Uuid::new_v4().to_string(),
            email: email.clone(),
            display_name: input.display_name,
            status: "pending".to_owned(),
            last_login_at: 0,
        };
        let invitation = IdentityInvitation {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            provider_id: input.provider_id,
            issuer: input.issuer,
            email,
            binding_policy: if input.binding_policy.trim().is_empty() {
                "verified_email_invitation".to_owned()
            } else {
                input.binding_policy
            },
            status: "pending".to_owned(),
            expires_at: input.expires_at,
            ..IdentityInvitation::default()
        };
        let mut state = self.inner.lock();
        state.users.insert(user.id.clone(), user.clone());
        state
            .invitations
            .insert(invitation.id.clone(), invitation.clone());
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "user.invite",
            "user",
            user.id.clone(),
            format!("email={} invitation_id={}", user.email, invitation.id),
        ));
        Ok((user, invitation))
    }

    async fn disable_user(&self, user_id_or_email: &str) -> Result<(), CoreError> {
        let mut state = self.inner.lock();
        let user_id = resolve_user_id(&state, user_id_or_email)?.to_owned();
        let user = state.users.get_mut(&user_id).ok_or(CoreError::NotFound)?;
        user.status = "disabled".to_owned();
        let email = user.email.clone();
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "user.disable",
            "user",
            user_id,
            format!("email={email}"),
        ));
        Ok(())
    }

    async fn enable_user(&self, user_id_or_email: &str) -> Result<(), CoreError> {
        let mut state = self.inner.lock();
        let user_id = resolve_user_id(&state, user_id_or_email)?.to_owned();
        let user = state.users.get_mut(&user_id).ok_or(CoreError::NotFound)?;
        if user.status == "deleted" {
            return Err(CoreError::NotFound);
        }
        user.status = "active".to_owned();
        let email = user.email.clone();
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "user.enable",
            "user",
            user_id,
            format!("email={email}"),
        ));
        Ok(())
    }
}

#[async_trait]
impl AccountQuery for AuditedStore {
    async fn user_by_id(&self, user_id: &str) -> Result<User, CoreError> {
        self.inner.user_by_id(user_id).await
    }

    async fn list_users(&self, filter: UserListFilter) -> Result<Vec<User>, CoreError> {
        self.inner.list_users(filter).await
    }
}

#[async_trait]
impl ResourceStore for AuditedStore {
    async fn upsert(&self, resource: Resource) -> Result<(), CoreError> {
        let mut resource = normalize_resource_for_upsert(resource)?;
        if resource.id.is_empty() {
            resource.id = uuid::Uuid::new_v4().to_string();
        }
        if resource.status.is_empty() {
            resource.status = "active".to_owned();
        }
        let mut state = self.inner.lock();
        state
            .resources
            .insert(resource.resource_id.clone(), resource.clone());
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "repository.add",
            "repository",
            resource.resource_id.clone(),
            format!(
                "name={} lore_repository_id={}",
                resource.name, resource.lore_repository_id
            ),
        ));
        Ok(())
    }

    async fn delete(&self, resource_id: &str) -> Result<(), CoreError> {
        let mut state = self.inner.lock();
        let id =
            lore_auth_core::model::ResourceID::for_repository_id(resource_id).ok_or_else(|| {
                CoreError::InvalidArgument("resource_id must not be empty".to_owned())
            })?;
        let resource = state.resources.get_mut(&id).ok_or(CoreError::NotFound)?;
        resource.status = "deleted".to_owned();
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "repository.disable",
            "repository",
            id,
            String::new(),
        ));
        Ok(())
    }
}

#[async_trait]
impl ResourceQuery for AuditedStore {
    async fn get_by_id(&self, id: &str) -> Result<Resource, CoreError> {
        self.inner.get_by_id(id).await
    }

    async fn get_by_resource_id(&self, resource_id: &str) -> Result<Resource, CoreError> {
        self.inner.get_by_resource_id(resource_id).await
    }

    async fn get_by_name(&self, name: &str) -> Result<Resource, CoreError> {
        self.inner.get_by_name(name).await
    }

    async fn list(&self) -> Result<Vec<Resource>, CoreError> {
        self.inner.list().await
    }
}
