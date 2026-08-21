from __future__ import annotations
from dataclasses import dataclass


@dataclass
class Credential:
    id: int
    service: str
    username: str
    password: str
    note: str = ""
    note_is_hidden: bool = False
    created_at: str | None = None

    @classmethod
    def from_row(cls, row: dict) -> "Credential":
        return cls(
            id=row["id"],
            service=row["service"],
            username=row["username"],
            password=row["password"],
            note=row.get("note", ""),
            note_is_hidden=bool(row.get("note_is_hidden", False)),
            created_at=row.get("created_at"),
        )
