# Webhooks Relay Service (FastAPI)

Сервис принимает вебхуки от GitHub/GitVerse, запускает скан в backend
`https://backend-findwork.ru.tuna.am` (`POST /scan/start`), затем ждёт результат
`GET /scan/{scan_id}/report` и публикует комментарий в Pull/Merge Request.

Поток:
- `GitHub` или `GitVerse` -> `webhooks` -> `backend /scan/start` -> wait report -> comment in PR/MR

## 1) Локальный запуск

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
uvicorn app.main:app --reload --port 8000
```

Проверка:
- `GET http://localhost:8000/health` -> `{"status":"ok"}`

## 2) Конфиг `.env`

```env
BACKEND_BASE_URL=https://backend-findwork.ru.tuna.am
BACKEND_API_KEY=...
GITHUB_WEBHOOK_SECRET=...
GITVERSE_WEBHOOK_SECRET=...
GITHUB_TOKEN=...
GITVERSE_TOKEN=...
GITVERSE_API_BASE_URL=https://gitverse.ru/api/v4
SCAN_INTERACTIVE=false
DEFAULT_SCAN_QUERY=
REPORT_POLL_INTERVAL_SECONDS=10
REPORT_WAIT_TIMEOUT_SECONDS=1800
REPORT_COMMENT_MAX_CHARS=12000
INLINE_COMMENTS_MAX=20
```

Примечания:
- `BACKEND_API_KEY` отправляется как `Authorization: Bearer ...`.
- Если secret не задан, подпись вебхука не проверяется.
- `DEFAULT_SCAN_QUERY` необязателен; если пустой, запрос формируется автоматически.
- `GITHUB_TOKEN` нужен для комментариев в GitHub PR.
- `GITVERSE_TOKEN` нужен для комментариев в GitVerse MR/PR.
- `INLINE_COMMENTS_MAX` ограничивает количество inline-комментариев за один отчёт.

## 3) URL для webhook-ов

- GitHub: `POST /webhooks/github`
- GitVerse: `POST /webhooks/gitverse`

Пример публичного URL:
- `https://<your-domain>/webhooks/github`
- `https://<your-domain>/webhooks/gitverse`

## 4) Какие события обрабатываются

- GitHub: `push`, `pull_request` (и `ping` для проверки)
- GitVerse: `push`, `merge_request`, `pull_request`

Остальные события возвращаются как `ignored`.

## 5) Что отправляется в backend

На каждое поддерживаемое событие сервис делает:
- `POST {BACKEND_BASE_URL}/scan/start`

Тело запроса:

```json
{
  "repo_url": "https://example.org/repo.git",
  "interactive": false,
  "query": "Webhook-triggered security scan (github:push)"
}
```

## 6) Пример ответа relay endpoint

```json
{
  "ok": true,
  "provider": "github",
  "event": "push",
  "delivery": "12345",
  "repo_url": "https://github.com/org/repo.git",
  "backend_scan_id": "scan_abc123",
  "comment_scheduled": true
}
```

## 7) Как формируется комментарий

- Для GitHub: комментарий идёт в `issues/{pr_number}/comments`.
- Для GitVerse: комментарий идёт в `projects/{project_id}/merge_requests/{iid}/notes`.
- Текст комментария содержит:
  - scan id
  - итоговый статус (`completed`/`failed`/`timeout`)
  - найденный отчёт backend (с ограничением длины `REPORT_COMMENT_MAX_CHARS`).

## 8) Inline-комментарии по строкам кода

Если в отчёте есть строки формата `Файл: app/main.py:26`, сервис пытается создать
inline-комментарий прямо на этой строке в PR/MR.

- GitHub: через review comments API (`pulls/{pr}/comments`).
- GitVerse: через discussions API (`merge_requests/{iid}/discussions`).
- Если inline-комментарий нельзя поставить (например, строка не входит в diff),
  сервис автоматически делает fallback в обычный общий комментарий.
