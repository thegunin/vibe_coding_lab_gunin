"""Main entry point for the Telegram feedback bot."""

from __future__ import annotations

import asyncio
import csv
import io
import logging
from dataclasses import dataclass
from typing import Iterable, Sequence

from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    ReplyKeyboardMarkup,
    ReplyKeyboardRemove,
    Update,
)
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ConversationHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from .config import Settings, load_settings
from .database import Database, QuestionStats
from .security import verify_password


logger = logging.getLogger(__name__)

# Conversation states
LOGIN_USERNAME, LOGIN_PASSWORD = range(2)
QUESTION_TEXT = 10


@dataclass(slots=True, frozen=True)
class SessionUser:
    """Lightweight representation of the logged-in account."""

    user_id: int
    login: str
    role: str


def build_keyboard_for_user(user: SessionUser | None) -> ReplyKeyboardMarkup:
    """Return ReplyKeyboardMarkup for current role."""
    if user is None:
        buttons = [["Войти"]]
    elif user.role == "employee":
        buttons = [["Вопросы", "Мои ответы"], ["Сменить аккаунт"]]
    else:
        buttons = [["Создать вопрос", "Отчёты"], ["Уведомления", "Сменить аккаунт"]]
    return ReplyKeyboardMarkup(buttons, resize_keyboard=True)


async def db_call(func, *args, **kwargs):
    """Run blocking DB call in default executor."""
    return await asyncio.to_thread(func, *args, **kwargs)


async def get_session_user(update: Update, context: ContextTypes.DEFAULT_TYPE, db: Database) -> SessionUser | None:
    """Ensure session user is cached in context.user_data."""
    session_user: SessionUser | None = context.user_data.get("user")
    if session_user:
        return session_user

    telegram_user = update.effective_user
    if not telegram_user:
        return None

    row = await db_call(db.fetch_user_by_telegram, telegram_user.id)
    if not row:
        return None

    session_user = SessionUser(user_id=row["id"], login=row["login"], role=row["role"])
    context.user_data["user"] = session_user
    return session_user


async def set_session_user(context: ContextTypes.DEFAULT_TYPE, user: SessionUser | None) -> None:
    if user is None:
        context.user_data.pop("user", None)
    else:
        context.user_data["user"] = user


async def send_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE, user: SessionUser | None) -> None:
    chat = update.effective_chat
    if not chat:
        return

    keyboard = build_keyboard_for_user(user)
    if user is None:
        text = (
            "Привет! Это бот для сбора обратной связи.\n"
            "Нажмите «Войти», чтобы выбрать учётную запись."
        )
    elif user.role == "employee":
        text = f"Добро пожаловать, {user.login}! Выберите действие."
    else:
        text = f"Здравствуйте, {user.login}! Выберите действие."

    await context.bot.send_message(chat_id=chat.id, text=text, reply_markup=keyboard)


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE, db: Database) -> None:
    user = await get_session_user(update, context, db)
    await send_main_menu(update, context, user)


try:  # pragma: no cover - runtime import fallback
    from .config import Settings, load_settings
    from .database import Database, QuestionStats
    from .security import verify_password
except ImportError:  # direct script execution
    import sys
    from pathlib import Path

    ROOT = Path(__file__).resolve().parent.parent
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

    from config import Settings, load_settings  # type: ignore
    from database import Database, QuestionStats  # type: ignore
    from security import verify_password  # type: ignore


# --- Authentication flow ----------------------------------------------------

async def login_entry(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("Введите логин:", reply_markup=ReplyKeyboardRemove())
    return LOGIN_USERNAME


async def login_receive_username(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data["login_attempt"] = {"login": update.message.text.strip()}
    await update.message.reply_text("Введите пароль:")
    return LOGIN_PASSWORD


async def login_receive_password(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    db: Database,
    settings: Settings,
) -> int:
    attempt = context.user_data.get("login_attempt", {})
    login = attempt.get("login")
    password = update.message.text

    if not login:
        await update.message.reply_text("Что-то пошло не так. Попробуйте войти снова.")
        return ConversationHandler.END

    user_row = await db_call(db.fetch_user_by_login, login)
    if not user_row:
        await update.message.reply_text("Неверный логин или пароль. Попробуйте снова.")
        return ConversationHandler.END
    if user_row["is_blocked"]:
        await update.message.reply_text("Учётная запись заблокирована. Обратитесь к администратору.")
        return ConversationHandler.END
    if not verify_password(password, settings.password_salt, user_row["password_hash"]):
        await update.message.reply_text("Неверный логин или пароль. Попробуйте снова.")
        return ConversationHandler.END

    telegram_user = update.effective_user
    if not telegram_user:
        await update.message.reply_text("Не удалось определить Telegram-пользователя.")
        return ConversationHandler.END

    await db_call(db.link_telegram_account, telegram_user.id, user_row["id"])
    session_user = SessionUser(user_id=user_row["id"], login=user_row["login"], role=user_row["role"])
    await set_session_user(context, session_user)

    await update.message.reply_text(
        f"Вход выполнен: {session_user.login}",
        reply_markup=build_keyboard_for_user(session_user),
    )
    context.user_data.pop("login_attempt", None)
    return ConversationHandler.END


async def login_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("Вход отменён.", reply_markup=build_keyboard_for_user(context.user_data.get("user")))
    context.user_data.pop("login_attempt", None)
    return ConversationHandler.END


async def logout(update: Update, context: ContextTypes.DEFAULT_TYPE, db: Database) -> None:
    telegram_user = update.effective_user
    if not telegram_user:
        return

    session_user = context.user_data.get("user")
    if not session_user:
        await update.message.reply_text("Вы ещё не вошли.", reply_markup=build_keyboard_for_user(None))
        return

    await db_call(db.unlink_telegram_account, telegram_user.id)
    await set_session_user(context, None)
    await update.message.reply_text("Вы вышли из аккаунта.", reply_markup=build_keyboard_for_user(None))


# --- Employee flows ---------------------------------------------------------

async def handle_questions(update: Update, context: ContextTypes.DEFAULT_TYPE, db: Database) -> None:
    user = await get_session_user(update, context, db)
    if not user or user.role != "employee":
        await update.message.reply_text("Доступно только сотрудникам.")
        return

    rows = await db_call(db.get_active_questions_for_employee, user.user_id)
    if not rows:
        await update.message.reply_text("Нет активных вопросов для ответа.")
        return

    for row in rows:
        keyboard = InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton(str(score), callback_data=f"answer:{row['id']}:{score}")
                    for score in range(1, 6)
                ]
            ]
        )
        preview = (row["text"][:77] + "...") if len(row["text"]) > 80 else row["text"]
        await update.message.reply_text(
            f"Вопрос #{row['id']}:\n{preview}",
            reply_markup=keyboard,
        )


async def handle_my_answers(update: Update, context: ContextTypes.DEFAULT_TYPE, db: Database) -> None:
    user = await get_session_user(update, context, db)
    if not user or user.role != "employee":
        await update.message.reply_text("Доступно только сотрудникам.")
        return

    rows = await db_call(db.list_answers_for_user, user.user_id, 10)
    if not rows:
        await update.message.reply_text("Ответов пока нет.")
        return

    for row in rows:
        text = (
            f"Вопрос #{row['question_id']}:\n"
            f"{row['question_text']}\n"
            f"Оценка: {row['score']}/5\n"
            f"Обновлён: {row['updated_at']}"
        )
        if row["question_status"] == "active":
            keyboard = InlineKeyboardMarkup(
                [
                    [
                        InlineKeyboardButton(str(score), callback_data=f"answer:{row['question_id']}:{score}")
                        for score in range(1, 6)
                    ]
                ]
            )
        else:
            keyboard = None
            text += "\n(Вопрос закрыт, изменить нельзя.)"

        await update.message.reply_text(text, reply_markup=keyboard)


async def handle_answer_callback(update: Update, context: ContextTypes.DEFAULT_TYPE, db: Database) -> None:
    query = update.callback_query
    await query.answer()

    user = await get_session_user(update, context, db)
    if not user or user.role != "employee":
        await query.edit_message_text("Доступно только сотрудникам.")
        return

    try:
        _, question_id_str, score_str = query.data.split(":")
        question_id = int(question_id_str)
        score = int(score_str)
    except (ValueError, AttributeError):
        await query.edit_message_text("Некорректные данные ответа.")
        return

    question = await db_call(db.fetch_question, question_id)
    if not question or question["status"] != "active":
        await query.edit_message_text("Вопрос недоступен или уже закрыт.")
        return

    answer_id, is_update = await db_call(db.upsert_answer, question_id, user.user_id, score)
    action = "обновил ответ" if is_update else "ответил"

    await query.edit_message_text(f"Ответ сохранён: {score}/5")

    payload_text = f"{user.login} {action} на «{question['text']}» — {score}/5"
    manager_ids = await db_call(db.list_user_ids_by_role, "manager")
    await db_call(
        db.add_notification,
        question_id,
        answer_id,
        manager_ids,
        payload_text,
        "answer_updated" if is_update else "answer_created",
    )

    telegram_ids = await db_call(db.list_telegram_ids_for_users, manager_ids)
    for telegram_id in telegram_ids:
        try:
            await context.bot.send_message(chat_id=telegram_id, text=payload_text)
        except Exception as exc:
            logger.warning("Failed to send notification to %s: %s", telegram_id, exc)


# --- Manager flows ----------------------------------------------------------

async def manager_only(update: Update, context: ContextTypes.DEFAULT_TYPE, db: Database) -> SessionUser | None:
    user = await get_session_user(update, context, db)
    if not user or user.role != "manager":
        if update.message:
            await update.message.reply_text("Функция доступна только руководителю.")
        elif update.callback_query:
            await update.callback_query.answer("Недостаточно прав.", show_alert=True)
        return None
    return user


async def create_question_entry(update: Update, context: ContextTypes.DEFAULT_TYPE, db: Database) -> int:
    user = await manager_only(update, context, db)
    if not user:
        return ConversationHandler.END

    await update.message.reply_text("Введите текст вопроса:", reply_markup=ReplyKeyboardRemove())
    return QUESTION_TEXT


async def create_question_save(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    db: Database,
) -> int:
    user: SessionUser | None = context.user_data.get("user")
    if not user or user.role != "manager":
        await update.message.reply_text("Сессия устарела. Повторите команду.")
        return ConversationHandler.END

    text = update.message.text.strip()
    if not text:
        await update.message.reply_text("Текст вопроса не может быть пустым. Введите снова.")
        return QUESTION_TEXT

    question_id = await db_call(db.create_question, text, user.user_id)
    await update.message.reply_text(
        f"Вопрос #{question_id} создан и доступен для ответов.",
        reply_markup=build_keyboard_for_user(user),
    )
    return ConversationHandler.END


async def create_question_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user: SessionUser | None = context.user_data.get("user")
    await update.message.reply_text("Создание вопроса отменено.", reply_markup=build_keyboard_for_user(user))
    return ConversationHandler.END


async def send_reports_page(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    db: Database,
    offset: int = 0,
) -> None:
    user = await manager_only(update, context, db)
    if not user:
        return

    limit = 10
    rows = await db_call(db.list_questions, limit, offset)
    if not rows:
        target = update.message or update.callback_query.message
        await target.reply_text("Вопросы не найдены.")
        return

    target = update.message or update.callback_query.message
    for row in rows:
        status = "активен" if row["status"] == "active" else "закрыт"
        avg = f"{row['average_score']:.2f}" if row["average_score"] else "—"
        text = (
            f"#{row['id']} • «{row['text']}»\n"
            f"Средний балл: {avg}\n"
            f"Ответов: {row['responses_total']}\n"
            f"Статус: {status}"
        )
        toggle_label = "Закрыть" if row["status"] == "active" else "Открыть"
        keyboard = InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton("Детали", callback_data=f"reports:details:{row['id']}"),
                    InlineKeyboardButton("Экспорт CSV", callback_data=f"reports:csv:{row['id']}"),
                ],
                [InlineKeyboardButton(toggle_label, callback_data=f"reports:toggle:{row['id']}")],
            ]
        )
        await target.reply_text(text, reply_markup=keyboard)

    if len(rows) == limit:
        keyboard = InlineKeyboardMarkup(
            [[InlineKeyboardButton("Следующая страница", callback_data=f"reports:page:{offset + limit}")]]
        )
        await target.reply_text("Показаны последние вопросы.", reply_markup=keyboard)


async def reports_callback(update: Update, context: ContextTypes.DEFAULT_TYPE, db: Database) -> None:
    query = update.callback_query
    await query.answer()

    user = await manager_only(update, context, db)
    if not user:
        return

    parts = query.data.split(":")
    if len(parts) < 3:
        return

    action = parts[1]
    if action == "page":
        offset = int(parts[2])
        await send_reports_page(update, context, db, offset)
        return

    question_id = int(parts[2])
    if action == "details":
        stats = await db_call(db.fetch_question_stats, question_id)
        if not stats:
            await query.edit_message_text("Вопрос не найден.")
            return
        text = format_question_stats(stats)
        await query.edit_message_text(text, parse_mode=ParseMode.MARKDOWN)
    elif action == "csv":
        await send_question_csv(query, context, db, question_id)
    elif action == "toggle":
        question = await db_call(db.fetch_question, question_id)
        if not question:
            await query.edit_message_text("Вопрос не найден.")
            return
        new_status = "closed" if question["status"] == "active" else "active"
        await db_call(db.set_question_status, question_id, new_status)
        await query.edit_message_text(f"Статус вопроса #{question_id} обновлён на {new_status}.")
    else:
        await query.answer("Неизвестное действие.")


def format_question_stats(stats: QuestionStats) -> str:
    lines = [
        f"*Вопрос #{stats.question_id}*",
        f"Текст: {stats.question_text}",
        f"Статус: {'активен' if stats.status == 'active' else 'закрыт'}",
        f"Создан: {stats.created_at}",
    ]
    if stats.closed_at:
        lines.append(f"Закрыт: {stats.closed_at}")

    lines.extend(
        [
            f"Ответов: {stats.responses_total}",
            f"Средний балл: {stats.average_score if stats.average_score is not None else '—'}",
            f"Медиана: {stats.median_score if stats.median_score is not None else '—'}",
            f"Участие: {stats.participation_percent if stats.participation_percent is not None else '—'}%",
            "Распределение:",
        ]
    )

    for score, count in stats.distribution.items():
        lines.append(f"  {score}: {count}")

    return "\n".join(lines)


async def send_question_csv(
    query,
    context: ContextTypes.DEFAULT_TYPE,
    db: Database,
    question_id: int,
) -> None:
    rows = await db_call(db.get_answers_for_csv, question_id)
    if not rows:
        await query.edit_message_text("Ответов для экспорта нет.")
        return

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["question_id", "question_text", "employee_login", "score", "created_at"])
    for row in rows:
        writer.writerow([row["question_id"], row["question_text"], row["employee_login"], row["score"], row["created_at"]])

    buffer.seek(0)
    bytes_buffer = io.BytesIO(buffer.getvalue().encode("utf-8"))
    filename = f"question_{question_id}_answers.csv"
    await context.bot.send_document(
        chat_id=query.message.chat_id,
        document=bytes_buffer,
        filename=filename,
    )


# --- Notifications for manager ---------------------------------------------

async def handle_notifications(update: Update, context: ContextTypes.DEFAULT_TYPE, db: Database) -> None:
    user = await manager_only(update, context, db)
    if not user:
        return

    await send_notifications_page(update, context, db, user.user_id, 0)


async def send_notifications_page(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    db: Database,
    user_id: int,
    offset: int,
) -> None:
    limit = 10
    rows = await db_call(db.list_notifications, user_id, limit, offset)

    target = update.message or update.callback_query.message
    if not rows:
        await target.reply_text("Уведомлений пока нет.")
        return

    lines = []
    unread_ids = []
    for row in rows:
        status = "новое" if not row["is_read"] else "прочитано"
        lines.append(f"[{row['id']}] {row['payload']} ({row['created_at']}) — {status}")
        if not row["is_read"]:
            unread_ids.append(row["id"])

    keyboard_rows = []
    if unread_ids:
        ids_payload = "_".join(str(i) for i in unread_ids)
        keyboard_rows.append([InlineKeyboardButton("Отметить как прочитанные", callback_data=f"notify:read:{ids_payload}")])
    if len(rows) == limit:
        keyboard_rows.append([InlineKeyboardButton("Следующая страница", callback_data=f"notify:page:{offset + limit}")])

    keyboard = InlineKeyboardMarkup(keyboard_rows) if keyboard_rows else None
    await target.reply_text("\n".join(lines), reply_markup=keyboard)


async def notifications_callback(update: Update, context: ContextTypes.DEFAULT_TYPE, db: Database) -> None:
    query = update.callback_query
    await query.answer()

    user = await manager_only(update, context, db)
    if not user:
        return

    try:
        _, action, payload = query.data.split(":")
    except ValueError:
        await query.answer("Некорректный запрос.")
        return

    if action == "page":
        offset = int(payload)
        await send_notifications_page(update, context, db, user.user_id, offset)
    elif action == "read":
        ids = [int(item) for item in payload.split("_") if item]
        await db_call(db.mark_notifications_read, ids)
        await query.edit_message_text("Выбранные уведомления отмечены как прочитанные.")
    else:
        await query.answer("Неизвестное действие.")


# --- Misc -------------------------------------------------------------------

async def unknown_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("Не понял запрос. Используйте меню.")


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.exception("Unhandled error: %s", context.error)
    if isinstance(update, Update):
        chat = update.effective_chat
        if chat:
            await context.bot.send_message(chat_id=chat.id, text="Что-то пошло не так. Попробуйте позже.")


def build_application(settings: Settings) -> Application:
    logging.basicConfig(level=getattr(logging, settings.log_level, logging.INFO))

    db = Database(settings.database_path)
    db.initialize(settings.password_salt)

    application = Application.builder().token(settings.bot_token).build()

    application.add_handler(CommandHandler("start", lambda update, context: start_command(update, context, db)))

    login_conv = ConversationHandler(
        entry_points=[MessageHandler(filters.Regex("^Войти$"), login_entry)],
        states={
            LOGIN_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, login_receive_username)],
            LOGIN_PASSWORD: [
                MessageHandler(
                    filters.TEXT & ~filters.COMMAND,
                    lambda update, context: login_receive_password(update, context, db, settings),
                )
            ],
        },
        fallbacks=[MessageHandler(filters.Regex("^Отмена$"), login_cancel)],
    )
    application.add_handler(login_conv)

    application.add_handler(MessageHandler(filters.Regex("^Сменить аккаунт$"), lambda u, c: logout(u, c, db)))

    application.add_handler(MessageHandler(filters.Regex("^Вопросы$"), lambda u, c: handle_questions(u, c, db)))
    application.add_handler(MessageHandler(filters.Regex("^Мои ответы$"), lambda u, c: handle_my_answers(u, c, db)))

    question_conv = ConversationHandler(
        entry_points=[MessageHandler(filters.Regex("^Создать вопрос$"), lambda u, c: create_question_entry(u, c, db))],
        states={
            QUESTION_TEXT: [MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: create_question_save(u, c, db))],
        },
        fallbacks=[MessageHandler(filters.Regex("^Отмена$"), create_question_cancel)],
    )
    application.add_handler(question_conv)

    application.add_handler(MessageHandler(filters.Regex("^Отчёты$"), lambda u, c: send_reports_page(u, c, db)))
    application.add_handler(MessageHandler(filters.Regex("^Уведомления$"), lambda u, c: handle_notifications(u, c, db)))

    application.add_handler(CallbackQueryHandler(lambda u, c: handle_answer_callback(u, c, db), pattern=r"^answer:"))
    application.add_handler(CallbackQueryHandler(lambda u, c: reports_callback(u, c, db), pattern=r"^reports:"))
    application.add_handler(CallbackQueryHandler(lambda u, c: notifications_callback(u, c, db), pattern=r"^notify:"))

    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, unknown_message))
    application.add_error_handler(error_handler)

    application.bot_data["db"] = db
    return application


def main() -> None:
    settings = load_settings()
    application = build_application(settings)
    application.run_polling()


if __name__ == "__main__":
    main()
