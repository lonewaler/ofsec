"""User persistence repository."""
from datetime import datetime, timezone

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User
from app.core.security import hash_password, verify_password


class UserRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_email(self, email: str) -> User | None:
        r = await self.db.execute(
            select(User).where(User.email == email.lower())
        )
        return r.scalar_one_or_none()

    async def get_by_id(self, user_id: int) -> User | None:
        return await self.db.get(User, user_id)

    async def count(self) -> int:
        r = await self.db.execute(select(func.count(User.id)))
        return r.scalar_one()

    async def list_all(self) -> list[User]:
        r = await self.db.execute(select(User).order_by(User.created_at))
        return r.scalars().all()

    async def create(
        self,
        email: str,
        password: str,
        display_name: str = "",
        role: str = "admin",
    ) -> User:
        user = User(
            email=email.lower(),
            password_hash=hash_password(password),
            display_name=display_name or email.split("@")[0].capitalize(),
            role=role,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(user)
        await self.db.flush()
        return user

    async def authenticate(self, email: str, password: str) -> User | None:
        user = await self.get_by_email(email)
        if not user or not user.is_active:
            return None
        if not verify_password(password, user.password_hash):
            return None
        user.last_login = datetime.now(timezone.utc)
        return user

    async def change_password(
        self, user_id: int, old_password: str, new_password: str
    ) -> tuple[bool, str]:
        user = await self.get_by_id(user_id)
        if not user:
            return False, "User not found"
        if not verify_password(old_password, user.password_hash):
            return False, "Current password incorrect"
        if len(new_password) < 8:
            return False, "New password must be at least 8 characters"
        user.password_hash = hash_password(new_password)
        return True, ""
