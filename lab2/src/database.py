"""SQLite persistence layer for the feedback bot."""

from __future__ import annotations

import sqlite3
import threading
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from statistics import median
from typing import Any, Iterable, Sequence

from .security import hash_password


QUESTION_STATUSES = ("active", "closed")
NOTIFICATION_TYPES = ("answer_created", "answer_updated")


@dataclass(frozen=True)
class QuestionStats:
    """Aggregated statistics for a question."""

    question_id: int
    question_text: str
    status: str
    created_at: str
    closed_at: str | None
    average_score: float | None
    median_score: float | None
    responses_total: int
    distribution: dict[int, int]
    participation_percent: float | None


@dataclass(frozen=True)
class ImportResult:
    """Summary for CSV imports."""

    questions_created: int
    questions_updated: int
    answers_inserted: int
    answers_updated: int


class Database:
    """Thin wrapper around sqlite3 for application-specific queries."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._initialized = False

    def connect(self) -> sqlite3.Connection:
        """Return configured connection."""
        conn = sqlite3.connect(self._path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self, password_salt: str) -> None:
        """Create tables and seed demo accounts once."""
        with self._lock:
            if self._initialized:
                return

            self._path.parent.mkdir(parents=True, exist_ok=True)

            with self.connect() as conn:
                self._create_schema(conn)
                self._seed_users(conn, password_salt)

            self._initialized = True

    def _create_schema(self, conn: sqlite3.Connection) -> None:
        cursor = conn.cursor()

        cursor.executescript(
            """
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('manager', 'employee')),
                is_blocked INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS telegram_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_user_id INTEGER NOT NULL UNIQUE,
                user_id INTEGER NOT NULL,
                linked_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'closed')),
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                closed_at TEXT,
                created_by INTEGER NOT NULL,
                FOREIGN KEY(created_by) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS answers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                question_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                score INTEGER NOT NULL CHECK(score BETWEEN 1 AND 5),
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(question_id, user_id),
                FOREIGN KEY(question_id) REFERENCES questions(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                question_id INTEGER NOT NULL,
                answer_id INTEGER NOT NULL,
                recipient_user_id INTEGER NOT NULL,
                payload TEXT NOT NULL,
                type TEXT NOT NULL CHECK(type IN ('answer_created', 'answer_updated')),
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(question_id) REFERENCES questions(id) ON DELETE CASCADE,
                FOREIGN KEY(answer_id) REFERENCES answers(id) ON DELETE CASCADE,
                FOREIGN KEY(recipient_user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
        self._ensure_question_import_column(conn)

    def _ensure_question_import_column(self, conn: sqlite3.Connection) -> None:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(questions);")}
        if "import_key" not in columns:
            conn.execute("ALTER TABLE questions ADD COLUMN import_key TEXT;")
            conn.commit()

        existing_indexes = {row[1] for row in conn.execute("PRAGMA index_list(questions);")}
        if "idx_questions_import_key" not in existing_indexes:
            conn.execute("CREATE UNIQUE INDEX idx_questions_import_key ON questions(import_key);")
            conn.commit()

    def _seed_users(self, conn: sqlite3.Connection, salt: str) -> None:
        existing = conn.execute("SELECT COUNT(*) FROM users;").fetchone()[0]
        if existing:
            return

        seed_data = [
            ("manager", "manager-password", "manager"),
            ("employee-1", "employee-1", "employee"),
            ("employee-2", "employee-2", "employee"),
            ("employee-3", "employee-3", "employee"),
        ]
        conn.executemany(
            """
            INSERT INTO users (login, password_hash, role)
            VALUES (?, ?, ?);
            """,
            [(login, hash_password(password, salt), role) for login, password, role in seed_data],
        )
        conn.commit()

    # --- User helpers -------------------------------------------------

    def fetch_user_by_login(self, login: str) -> sqlite3.Row | None:
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM users WHERE login = ?;",
                (login,),
            ).fetchone()

    def fetch_user_by_id(self, user_id: int) -> sqlite3.Row | None:
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM users WHERE id = ?;",
                (user_id,),
            ).fetchone()

    def fetch_user_by_telegram(self, telegram_user_id: int) -> sqlite3.Row | None:
        with self.connect() as conn:
            return conn.execute(
                """
                SELECT u.*
                FROM telegram_accounts ta
                JOIN users u ON ta.user_id = u.id
                WHERE ta.telegram_user_id = ?;
                """,
                (telegram_user_id,),
            ).fetchone()

    def link_telegram_account(self, telegram_user_id: int, user_id: int) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO telegram_accounts (telegram_user_id, user_id, linked_at)
                VALUES (?, ?, datetime('now'))
                ON CONFLICT(telegram_user_id) DO UPDATE
                SET user_id = excluded.user_id,
                    linked_at = datetime('now');
                """,
                (telegram_user_id, user_id),
            )
            conn.commit()

    def unlink_telegram_account(self, telegram_user_id: int) -> None:
        with self.connect() as conn:
            conn.execute(
                "DELETE FROM telegram_accounts WHERE telegram_user_id = ?;",
                (telegram_user_id,),
            )
            conn.commit()

    def count_logged_in_employees(self) -> int:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(DISTINCT u.id) AS total
                FROM telegram_accounts ta
                JOIN users u ON ta.user_id = u.id
                WHERE u.role = 'employee';
                """
            ).fetchone()
        return row["total"] if row else 0

    def list_user_ids_by_role(self, role: str) -> list[int]:
        if role not in {"manager", "employee"}:
            raise ValueError("role must be 'manager' or 'employee'")
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id FROM users WHERE role = ? AND is_blocked = 0;",
                (role,),
            ).fetchall()
        return [row["id"] for row in rows]

    def list_telegram_ids_for_users(self, user_ids: Sequence[int]) -> list[int]:
        if not user_ids:
            return []
        placeholders = ",".join("?" for _ in user_ids)
        with self.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT telegram_user_id
                FROM telegram_accounts
                WHERE user_id IN ({placeholders});
                """,
                tuple(user_ids),
            ).fetchall()
        return [row["telegram_user_id"] for row in rows]

    # --- Question helpers ---------------------------------------------

    def create_question(self, text: str, author_id: int) -> int:
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO questions (text, status, created_by)
                VALUES (?, 'active', ?);
                """,
                (text, author_id),
            )
            conn.commit()
            return cursor.lastrowid

    def fetch_question(self, question_id: int) -> sqlite3.Row | None:
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM questions WHERE id = ?;",
                (question_id,),
            ).fetchone()

    def list_questions(self, limit: int, offset: int = 0) -> list[sqlite3.Row]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT q.*,
                       COALESCE(stats.average_score, 0) AS average_score,
                       COALESCE(stats.responses_total, 0) AS responses_total
                FROM questions q
                LEFT JOIN (
                    SELECT question_id,
                           AVG(score) AS average_score,
                           COUNT(*) AS responses_total
                    FROM answers
                    GROUP BY question_id
                ) stats ON stats.question_id = q.id
                ORDER BY q.created_at DESC
                LIMIT ? OFFSET ?;
                """,
                (limit, offset),
            ).fetchall()
        return list(rows)

    def set_question_status(self, question_id: int, status: str) -> None:
        if status not in QUESTION_STATUSES:
            raise ValueError(f"Unsupported question status: {status}")

        closed_at_expr = "datetime('now')" if status == "closed" else "NULL"

        with self.connect() as conn:
            conn.execute(
                f"""
                UPDATE questions
                SET status = ?, closed_at = {closed_at_expr}
                WHERE id = ?;
                """,
                (status, question_id),
            )
            conn.commit()

    # --- Answer helpers -----------------------------------------------

    def fetch_question_by_import_key(self, import_key: str) -> sqlite3.Row | None:
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM questions WHERE import_key = ?;",
                (import_key,),
            ).fetchone()

    def import_historical_answers(
        self,
        rows: Sequence[dict[str, Any]],
        manager_user_id: int,
    ) -> ImportResult:
        """Upsert questions and answers imported from CSV."""

        if not rows:
            return ImportResult(0, 0, 0, 0)

        questions_created = 0
        questions_updated = 0
        answers_inserted = 0
        answers_updated = 0
        cache: dict[str, int] = {}

        with self.connect() as conn:
            conn.execute("BEGIN")
            for item in rows:
                import_key = item["import_key"]
                question_id = cache.get(import_key)

                if question_id is None:
                    existing = conn.execute(
                        "SELECT id FROM questions WHERE import_key = ?;",
                        (import_key,),
                    ).fetchone()

                    payload = (
                        item["question_text"],
                        item["question_status"],
                        item["question_created_at"],
                        item["question_closed_at"],
                        manager_user_id,
                        import_key,
                    )

                    if existing:
                        question_id = existing["id"]
                        conn.execute(
                            """
                            UPDATE questions
                            SET text = ?,
                                status = ?,
                                created_at = ?,
                                closed_at = ?,
                                created_by = ?
                            WHERE id = ?;
                            """,
                            payload[:5] + (question_id,),
                        )
                        questions_updated += 1
                    else:
                        cursor = conn.execute(
                            """
                            INSERT INTO questions (text, status, created_at, closed_at, created_by, import_key)
                            VALUES (?, ?, ?, ?, ?, ?);
                            """,
                            payload,
                        )
                        question_id = cursor.lastrowid
                        questions_created += 1

                    cache[import_key] = question_id

                employee_id = item["user_id"]
                answer = conn.execute(
                    """
                    SELECT id FROM answers
                    WHERE question_id = ? AND user_id = ?;
                    """,
                    (question_id, employee_id),
                ).fetchone()

                answer_payload = (
                    item["score"],
                    item["answered_at"],
                    item["answered_at"],
                )

                if answer:
                    conn.execute(
                        """
                        UPDATE answers
                        SET score = ?,
                            created_at = ?,
                            updated_at = ?
                        WHERE id = ?;
                        """,
                        answer_payload + (answer["id"],),
                    )
                    answers_updated += 1
                else:
                    conn.execute(
                        """
                        INSERT INTO answers (question_id, user_id, score, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?);
                        """,
                        (question_id, employee_id, item["score"], item["answered_at"], item["answered_at"]),
                    )
                    answers_inserted += 1

            conn.commit()

        return ImportResult(questions_created, questions_updated, answers_inserted, answers_updated)

    def get_active_questions_for_employee(self, user_id: int) -> list[sqlite3.Row]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT q.id,
                       q.text,
                       q.created_at
                FROM questions q
                LEFT JOIN answers a
                    ON a.question_id = q.id AND a.user_id = ?
                WHERE q.status = 'active' AND a.id IS NULL
                ORDER BY q.created_at DESC;
                """,
                (user_id,),
            ).fetchall()
        return list(rows)

    def upsert_answer(self, question_id: int, user_id: int, score: int) -> tuple[int, bool]:
        """Insert or update an answer. Returns answer_id and whether it was an update."""
        now = datetime.utcnow().isoformat(timespec="seconds")
        with self.connect() as conn:
            cursor = conn.execute(
                """
                SELECT id, score FROM answers
                WHERE question_id = ? AND user_id = ?;
                """,
                (question_id, user_id),
            )
            existing = cursor.fetchone()

            if existing:
                conn.execute(
                    """
                    UPDATE answers
                    SET score = ?, updated_at = ?
                    WHERE id = ?;
                    """,
                    (score, now, existing["id"]),
                )
                conn.commit()
                return existing["id"], True

            cursor = conn.execute(
                """
                INSERT INTO answers (question_id, user_id, score, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?);
                """,
                (question_id, user_id, score, now, now),
            )
            conn.commit()
            return cursor.lastrowid, False

    def list_answers_for_user(self, user_id: int, limit: int = 10) -> list[sqlite3.Row]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT a.id,
                       a.question_id,
                       a.score,
                       a.updated_at,
                       q.text AS question_text,
                       q.status AS question_status
                FROM answers a
                JOIN questions q ON q.id = a.question_id
                WHERE a.user_id = ?
                ORDER BY a.updated_at DESC
                LIMIT ?;
                """,
                (user_id, limit),
            ).fetchall()
        return list(rows)

    def fetch_answer(self, question_id: int, user_id: int) -> sqlite3.Row | None:
        with self.connect() as conn:
            return conn.execute(
                """
                SELECT * FROM answers
                WHERE question_id = ? AND user_id = ?;
                """,
                (question_id, user_id),
            ).fetchone()

    def fetch_question_stats(self, question_id: int) -> QuestionStats | None:
        with self.connect() as conn:
            question = conn.execute(
                "SELECT * FROM questions WHERE id = ?;",
                (question_id,),
            ).fetchone()
            if not question:
                return None

            answers = conn.execute(
                """
                SELECT score
                FROM answers
                WHERE question_id = ?
                ORDER BY created_at ASC;
                """,
                (question_id,),
            ).fetchall()

        scores = [row["score"] for row in answers]
        total = len(scores)
        if total:
            avg_score = round(sum(scores) / total, 2)
            med_score = float(median(scores))
        else:
            avg_score = None
            med_score = None

        distribution = Counter(scores)
        for grade in range(1, 6):
            distribution.setdefault(grade, 0)

        logged_in_employees = self.count_logged_in_employees()
        participation = None
        if logged_in_employees:
            participation = round((total / logged_in_employees) * 100, 2)

        return QuestionStats(
            question_id=question["id"],
            question_text=question["text"],
            status=question["status"],
            created_at=question["created_at"],
            closed_at=question["closed_at"],
            average_score=avg_score,
            median_score=med_score,
            responses_total=total,
            distribution=dict(sorted(distribution.items())),
            participation_percent=participation,
        )

    def get_answers_for_csv(self, question_id: int) -> list[sqlite3.Row]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT a.question_id,
                       q.text AS question_text,
                       u.login AS employee_login,
                       a.score,
                       a.created_at
                FROM answers a
                JOIN users u ON u.id = a.user_id
                JOIN questions q ON q.id = a.question_id
                WHERE a.question_id = ?
                ORDER BY a.created_at ASC;
                """,
                (question_id,),
            ).fetchall()
        return list(rows)

    # --- Notifications ------------------------------------------------

    def add_notification(
        self,
        question_id: int,
        answer_id: int,
        recipient_ids: Sequence[int],
        payload: str,
        type_: str,
    ) -> None:
        if type_ not in NOTIFICATION_TYPES:
            raise ValueError(f"Unsupported notification type: {type_}")

        rows = [(question_id, answer_id, recipient_id, payload, type_) for recipient_id in recipient_ids]

        with self.connect() as conn:
            conn.executemany(
                """
                INSERT INTO notifications (question_id, answer_id, recipient_user_id, payload, type)
                VALUES (?, ?, ?, ?, ?);
                """,
                rows,
            )
            conn.commit()

    def list_notifications(self, recipient_id: int, limit: int, offset: int = 0) -> list[sqlite3.Row]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, payload, type, is_read, created_at
                FROM notifications
                WHERE recipient_user_id = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?;
                """,
                (recipient_id, limit, offset),
            ).fetchall()
        return list(rows)

    def mark_notifications_read(self, notification_ids: Iterable[int]) -> None:
        ids = list(notification_ids)
        if not ids:
            return
        placeholders = ",".join("?" for _ in ids)
        with self.connect() as conn:
            conn.execute(
                f"UPDATE notifications SET is_read = 1 WHERE id IN ({placeholders});",
                ids,
            )
            conn.commit()
