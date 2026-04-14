"""Password hashing and user DB operations for authentication."""

import bcrypt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.orm_models import User


def hash_password(plain: str) -> str:
    """Hash a plaintext password with bcrypt, cost factor=12."""
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time bcrypt comparison — returns True if plain matches hashed."""
    return bcrypt.checkpw(plain.encode(), hashed.encode())


async def get_user_by_email(session: AsyncSession, email: str) -> User | None:
    """Fetch a User row by email (case-insensitive — always stored lowercase)."""
    result = await session.execute(
        select(User).where(User.email == email.lower())
    )
    return result.scalar_one_or_none()


async def create_student_user(
    session: AsyncSession, email: str, password: str
) -> User:
    """Insert a new student user and return the persisted ORM instance."""
    user = User(
        email=email.lower(),
        password_hash=hash_password(password),
        role="student",
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user
