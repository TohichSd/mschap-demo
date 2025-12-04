# db.py
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import Column, Integer, String, LargeBinary, DateTime, func, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True, nullable=False, index=True)
    nt_hash = Column(LargeBinary(16), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self) -> str:
        return f"<User username={self.username!r}>"


@dataclass
class DatabaseConfig:
    user: str = os.getenv("DB_USER", "mschap")
    password: str = os.getenv("DB_PASSWORD", "mschap")
    host: str = os.getenv("DB_HOST", "localhost")
    port: int = int(os.getenv("DB_PORT", "5432"))
    db_name: str = os.getenv("DB_NAME", "mschap_db")

    @property
    def url(self) -> str:
        return f"postgresql+psycopg2://{self.user}:{self.password}@{self.host}:{self.port}/{self.db_name}"


class Database:
    """
    Класс над SQLAlchemy.
    """

    def __init__(self, config: Optional[DatabaseConfig] = None):
        self.config = config or DatabaseConfig()
        self.engine = create_engine(self.config.url, echo=False, future=True)
        self.SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False, future=True)

    def init_db(self) -> None:
        Base.metadata.create_all(bind=self.engine)

    def get_session(self) -> Session:
        return self.SessionLocal()

    # high-level методы
    def get_user_by_username(self, username: str) -> Optional[User]:
        with self.get_session() as session:
            return session.query(User).filter_by(username=username).first()

    def create_user(self, username: str, nt_hash: bytes) -> User:
        with self.get_session() as session:
            user = User(username=username, nt_hash=nt_hash)
            session.add(user)
            session.commit()
            session.refresh(user)
            return user
