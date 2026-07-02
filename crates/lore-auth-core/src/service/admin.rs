//! Admin write wrappers that record audit entries after successful mutations.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;

use crate::{
    CoreError,
    model::{self, AdminAuditEntry},
    ports::{AdminAuditLog, GrantAdmin, GroupAdmin},
};

static AUDIT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
/// Group administration wrapper that records audit entries after successful mutations.
///
/// This wrapper is mutation-first: if the inner mutation succeeds and audit recording
/// then fails, the mutation has already been persisted and the method returns
/// [`CoreError::AdminAuditFailed`].
pub struct AuditedGroupAdmin {
    inner: Arc<dyn GroupAdmin>,
    audit: Arc<dyn AdminAuditLog>,
    actor: String,
}

impl AuditedGroupAdmin {
    #[must_use]
    pub fn new<I, A>(inner: Arc<I>, audit: Arc<A>, actor: impl Into<String>) -> Self
    where
        I: GroupAdmin + 'static,
        A: AdminAuditLog + 'static,
    {
        Self {
            inner,
            audit,
            actor: actor.into(),
        }
    }

    async fn record(
        &self,
        action: &str,
        object_type: &str,
        object_id: impl Into<String>,
        detail: impl Into<String>,
    ) -> Result<(), CoreError> {
        record_admin_audit(
            self.audit.as_ref(),
            &self.actor,
            action,
            object_type,
            object_id,
            detail,
        )
        .await
    }
}

#[async_trait]
impl GroupAdmin for AuditedGroupAdmin {
    async fn add_group(&self, name: &str, description: &str) -> Result<model::Group, CoreError> {
        let group = self.inner.add_group(name, description).await?;
        self.record(
            "group.add",
            "group",
            group.id.clone(),
            format!("name={}", group.name),
        )
        .await?;
        Ok(group)
    }

    async fn list_groups(&self) -> Result<Vec<model::Group>, CoreError> {
        self.inner.list_groups().await
    }

    async fn list_group_members(&self, group: &str) -> Result<Vec<model::User>, CoreError> {
        self.inner.list_group_members(group).await
    }

    async fn list_group_groups(&self, group: &str) -> Result<Vec<model::Group>, CoreError> {
        self.inner.list_group_groups(group).await
    }

    async fn add_group_member(&self, group: &str, user_email_or_id: &str) -> Result<(), CoreError> {
        self.inner.add_group_member(group, user_email_or_id).await?;
        self.record(
            "group.member.add",
            "group",
            group,
            format!("user={user_email_or_id}"),
        )
        .await
    }

    async fn remove_group_member(
        &self,
        group: &str,
        user_email_or_id: &str,
    ) -> Result<(), CoreError> {
        self.inner
            .remove_group_member(group, user_email_or_id)
            .await?;
        self.record(
            "group.member.remove",
            "group",
            group,
            format!("user={user_email_or_id}"),
        )
        .await
    }

    async fn add_group_group(
        &self,
        parent_group: &str,
        member_group: &str,
    ) -> Result<(), CoreError> {
        self.inner
            .add_group_group(parent_group, member_group)
            .await?;
        self.record(
            "group.nest.add",
            "group",
            parent_group,
            format!("member_group={member_group}"),
        )
        .await
    }

    async fn remove_group_group(
        &self,
        parent_group: &str,
        member_group: &str,
    ) -> Result<(), CoreError> {
        self.inner
            .remove_group_group(parent_group, member_group)
            .await?;
        self.record(
            "group.nest.remove",
            "group",
            parent_group,
            format!("member_group={member_group}"),
        )
        .await
    }
}

#[derive(Clone)]
/// Grant administration wrapper that records audit entries after successful mutations.
///
/// This wrapper is mutation-first: if the inner mutation succeeds and audit recording
/// then fails, the mutation has already been persisted and the method returns
/// [`CoreError::AdminAuditFailed`].
pub struct AuditedGrantAdmin {
    inner: Arc<dyn GrantAdmin>,
    audit: Arc<dyn AdminAuditLog>,
    actor: String,
}

impl AuditedGrantAdmin {
    #[must_use]
    pub fn new<I, A>(inner: Arc<I>, audit: Arc<A>, actor: impl Into<String>) -> Self
    where
        I: GrantAdmin + 'static,
        A: AdminAuditLog + 'static,
    {
        Self {
            inner,
            audit,
            actor: actor.into(),
        }
    }

    async fn record(
        &self,
        action: &str,
        object_id: impl Into<String>,
        detail: impl Into<String>,
    ) -> Result<(), CoreError> {
        record_admin_audit(
            self.audit.as_ref(),
            &self.actor,
            action,
            "grant",
            object_id,
            detail,
        )
        .await
    }
}

#[async_trait]
impl GrantAdmin for AuditedGrantAdmin {
    async fn add_grant(
        &self,
        subject_type: &str,
        subject_id: &str,
        repo: &str,
        role: &str,
    ) -> Result<model::Grant, CoreError> {
        let grant = self
            .inner
            .add_grant(subject_type, subject_id, repo, role)
            .await?;
        self.record(
            "grant.add",
            grant.id.clone(),
            grant_detail(subject_type, subject_id, repo, role),
        )
        .await?;
        Ok(grant)
    }

    async fn remove_grant(
        &self,
        subject_type: &str,
        subject_id: &str,
        repo: &str,
        role: &str,
    ) -> Result<(), CoreError> {
        self.inner
            .remove_grant(subject_type, subject_id, repo, role)
            .await?;
        self.record(
            "grant.remove",
            format!("{subject_type}:{subject_id}:{repo}:{role}"),
            grant_detail(subject_type, subject_id, repo, role),
        )
        .await
    }

    async fn list_grants(&self, repo: &str) -> Result<Vec<model::Grant>, CoreError> {
        self.inner.list_grants(repo).await
    }
}

async fn record_admin_audit(
    audit: &dyn AdminAuditLog,
    actor: &str,
    action: &str,
    object_type: &str,
    object_id: impl Into<String>,
    detail: impl Into<String>,
) -> Result<(), CoreError> {
    audit
        .record(AdminAuditEntry {
            id: new_audit_id(),
            actor: actor.to_owned(),
            action: action.to_owned(),
            object_type: object_type.to_owned(),
            object_id: object_id.into(),
            detail: detail.into(),
            created_at: unix_now(),
        })
        .await
        .map_err(|err| CoreError::AdminAuditFailed(err.to_string()))
}

fn grant_detail(subject_type: &str, subject_id: &str, repo: &str, role: &str) -> String {
    format!("subject_type={subject_type} subject_id={subject_id} repo={repo} role={role}")
}

fn new_audit_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let sequence = AUDIT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("admin-audit-{nanos}-{sequence}")
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}
