"""Repository for User operations."""

from typing import Optional, List
from sqlalchemy import select, or_
from sqlalchemy.orm import Session, joinedload, selectinload

from ion.models.user import User, Role, Permission


class UserRepository:
    """Repository for User CRUD operations."""

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        username: str,
        email: str,
        password_hash: str,
        display_name: str | None = None,
        is_active: bool = True,
        must_change_password: bool = False,
    ) -> User:
        """Create a new user."""
        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            display_name=display_name,
            is_active=is_active,
            must_change_password=must_change_password,
        )
        self.session.add(user)
        self.session.flush()
        return user

    def get_by_id(self, user_id: int) -> Optional[User]:
        """Get a user by ID."""
        stmt = (
            select(User)
            .options(selectinload(User.roles).selectinload(Role.permissions))
            .where(User.id == user_id)
        )
        return self.session.execute(stmt).unique().scalar_one_or_none()

    def get_by_username(self, username: str) -> Optional[User]:
        """Get a user by username."""
        stmt = (
            select(User)
            .options(selectinload(User.roles).selectinload(Role.permissions))
            .where(User.username == username)
        )
        return self.session.execute(stmt).unique().scalar_one_or_none()

    def get_by_email(self, email: str) -> Optional[User]:
        """Get a user by email."""
        stmt = (
            select(User)
            .options(selectinload(User.roles).selectinload(Role.permissions))
            .where(User.email == email)
        )
        return self.session.execute(stmt).unique().scalar_one_or_none()

    def list_all(self, include_inactive: bool = False) -> List[User]:
        """List all users."""
        # v0.9.82: selectinload for M2M — was joinedload, producing a users × roles cartesian.
        stmt = select(User).options(selectinload(User.roles))

        if not include_inactive:
            stmt = stmt.where(User.is_active == True)

        stmt = stmt.order_by(User.username)
        return list(self.session.execute(stmt).scalars().all())

    def search(self, query: str) -> List[User]:
        """Search users by username, email, or display name."""
        pattern = f"%{query}%"
        stmt = (
            select(User)
            .options(selectinload(User.roles))
            .where(
                or_(
                    User.username.ilike(pattern),
                    User.email.ilike(pattern),
                    User.display_name.ilike(pattern),
                )
            )
            .order_by(User.username)
        )
        return list(self.session.execute(stmt).scalars().all())

    def update(
        self,
        user: User,
        username: str | None = None,
        email: str | None = None,
        display_name: str | None = None,
        is_active: bool | None = None,
        must_change_password: bool | None = None,
    ) -> User:
        """Update a user."""
        if username is not None:
            user.username = username
        if email is not None:
            user.email = email
        if display_name is not None:
            user.display_name = display_name
        if is_active is not None:
            user.is_active = is_active
        if must_change_password is not None:
            user.must_change_password = must_change_password
        self.session.flush()
        return user

    def update_password(self, user: User, password_hash: str) -> User:
        """Update user's password."""
        user.password_hash = password_hash
        user.must_change_password = False
        self.session.flush()
        return user

    def update_last_login(self, user: User) -> User:
        """Update user's last login timestamp."""
        from datetime import datetime
        user.last_login = datetime.utcnow()
        self.session.flush()
        return user

    def delete(self, user: User) -> None:
        """Delete a user."""
        self.session.delete(user)
        self.session.flush()

    def add_role(self, user: User, role: Role) -> None:
        """Add a role to a user."""
        if role not in user.roles:
            user.roles.append(role)
            self.session.flush()

    def remove_role(self, user: User, role: Role) -> None:
        """Remove a role from a user."""
        if role in user.roles:
            user.roles.remove(role)
            self.session.flush()

    def set_roles(self, user: User, roles: List[Role]) -> None:
        """Set user's roles (replaces existing roles)."""
        user.roles = roles
        self.session.flush()


class RoleRepository:
    """Repository for Role operations."""

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        name: str,
        description: str | None = None,
        is_system: bool = False,
    ) -> Role:
        """Create a new role."""
        role = Role(
            name=name,
            description=description,
            is_system=is_system,
        )
        self.session.add(role)
        self.session.flush()
        return role

    def get_by_id(self, role_id: int) -> Optional[Role]:
        """Get a role by ID."""
        # v0.9.82: selectinload — Role.permissions is M2M
        stmt = (
            select(Role)
            .options(selectinload(Role.permissions))
            .where(Role.id == role_id)
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def get_by_name(self, name: str) -> Optional[Role]:
        """Get a role by name."""
        stmt = (
            select(Role)
            .options(selectinload(Role.permissions))
            .where(Role.name == name)
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def list_all(self) -> List[Role]:
        """List all roles."""
        stmt = (
            select(Role)
            .options(selectinload(Role.permissions))
            .order_by(Role.name)
        )
        return list(self.session.execute(stmt).scalars().all())

    def delete(self, role: Role) -> None:
        """Delete a role."""
        self.session.delete(role)
        self.session.flush()

    def add_permission(self, role: Role, permission: Permission) -> None:
        """Add a permission to a role."""
        if permission not in role.permissions:
            role.permissions.append(permission)
            self.session.flush()

    def remove_permission(self, role: Role, permission: Permission) -> None:
        """Remove a permission from a role."""
        if permission in role.permissions:
            role.permissions.remove(permission)
            self.session.flush()

    def set_permissions(self, role: Role, permissions: List[Permission]) -> None:
        """Set role's permissions (replaces existing permissions)."""
        role.permissions = permissions
        self.session.flush()


class PermissionRepository:
    """Repository for Permission operations."""

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        name: str,
        resource: str,
        action: str,
        description: str | None = None,
    ) -> Permission:
        """Create a new permission."""
        permission = Permission(
            name=name,
            resource=resource,
            action=action,
            description=description,
        )
        self.session.add(permission)
        self.session.flush()
        return permission

    def get_by_id(self, permission_id: int) -> Optional[Permission]:
        """Get a permission by ID."""
        stmt = select(Permission).where(Permission.id == permission_id)
        return self.session.execute(stmt).scalar_one_or_none()

    def get_by_name(self, name: str) -> Optional[Permission]:
        """Get a permission by name."""
        stmt = select(Permission).where(Permission.name == name)
        return self.session.execute(stmt).scalar_one_or_none()

    def list_all(self) -> List[Permission]:
        """List all permissions."""
        stmt = select(Permission).order_by(Permission.resource, Permission.action)
        return list(self.session.execute(stmt).scalars().all())

    def list_by_resource(self, resource: str) -> List[Permission]:
        """List permissions for a specific resource."""
        stmt = (
            select(Permission)
            .where(Permission.resource == resource)
            .order_by(Permission.action)
        )
        return list(self.session.execute(stmt).scalars().all())

    def delete(self, permission: Permission) -> None:
        """Delete a permission."""
        self.session.delete(permission)
        self.session.flush()
