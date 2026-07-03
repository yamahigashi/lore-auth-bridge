//! Group administration and group query behavior for the memory adapter.

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{Group, User},
    ports::{GroupAdmin, GroupQuery},
};

use super::{
    Store, group_by_name_or_id, group_group_would_cycle, resolve_group_id, resolve_user_id,
};

#[async_trait]
impl GroupAdmin for Store {
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
        self.lock().groups.insert(group.name.clone(), group.clone());
        Ok(group)
    }

    async fn add_group_member(&self, group: &str, user_email_or_id: &str) -> Result<(), CoreError> {
        let mut state = self.lock();
        let user_id = resolve_user_id(&state, user_email_or_id)?.to_owned();
        state
            .group_members
            .entry(user_id)
            .or_default()
            .push(group.to_owned());
        Ok(())
    }

    async fn remove_group_member(
        &self,
        group: &str,
        user_email_or_id: &str,
    ) -> Result<(), CoreError> {
        let mut state = self.lock();
        let user_id = resolve_user_id(&state, user_email_or_id)?.to_owned();
        if let Some(groups) = state.group_members.get_mut(&user_id) {
            groups.retain(|name| name != group);
        }
        Ok(())
    }

    async fn add_group_group(
        &self,
        parent_group: &str,
        member_group: &str,
    ) -> Result<(), CoreError> {
        let mut state = self.lock();
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
        Ok(())
    }

    async fn remove_group_group(
        &self,
        parent_group: &str,
        member_group: &str,
    ) -> Result<(), CoreError> {
        let mut state = self.lock();
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
        Ok(())
    }
}

#[async_trait]
impl GroupQuery for Store {
    async fn list_groups(&self) -> Result<Vec<Group>, CoreError> {
        let mut out = self.lock().groups.values().cloned().collect::<Vec<_>>();
        out.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(out)
    }

    async fn list_group_members(&self, group: &str) -> Result<Vec<User>, CoreError> {
        let state = self.lock();
        let group = group_by_name_or_id(&state, group)?;
        let mut out = state
            .group_members
            .iter()
            .filter(|(_, groups)| {
                groups
                    .iter()
                    .any(|member| member == &group.id || member == &group.name)
            })
            .filter_map(|(user_id, _)| {
                state
                    .users
                    .get(user_id)
                    .filter(|user| user.status != "deleted")
                    .cloned()
            })
            .collect::<Vec<_>>();
        out.sort_by(|left, right| {
            let left_key = (
                lore_auth_core::model::normalize_email(&left.email),
                &left.id,
            );
            let right_key = (
                lore_auth_core::model::normalize_email(&right.email),
                &right.id,
            );
            left_key.cmp(&right_key)
        });
        Ok(out)
    }

    async fn list_group_groups(&self, group: &str) -> Result<Vec<Group>, CoreError> {
        let state = self.lock();
        let group = group_by_name_or_id(&state, group)?;
        let mut out = state
            .group_groups
            .get(&group.id)
            .into_iter()
            .flatten()
            .filter_map(|group_id| state.groups.values().find(|group| group.id == *group_id))
            .cloned()
            .collect::<Vec<_>>();
        out.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(out)
    }
}
