Конвертер документов (PDF ↔ Word) на Flask

📌 Описание проекта:
Веб-приложение для конвертации файлов между форматами PDF и Word (DOCX/DOC) с авторизацией пользователей и историей операций.

🌟 Основные функции

Конвертация форматов: PDF → Word (DOCX) и Word (DOCX/DOC) → PDF

Система пользователей: Регистрация/авторизация. Персональная история конвертаций.

Дополнительные возможности: Экспорт истории в CSV. Удаление записей. Логирование операций

⚙️ Технологический стек
Backend: Python 3, Flask

База данных: SQLite (через SQLAlchemy)

Безопасность: Werkzeug password hashing

Конвертация: PDF → Word: pdf2docx; Word → PDF: docx2pdf

🛠 Установка и запуск

Требования: pip install flask flask-sqlalchemy flask-login werkzeug pdf2docx docx2pdf

Запуск: python app.py

Приложение запустится в режиме отладки на http://localhost:5000

Первоначальная настройка:

Файлы БД (users.db) и папки (uploads/, outputs/) создаются автоматически

Логи пишутся в app.log (макс. 10 КБ + 1 бэкап)

🔒 Безопасность

Хеширование паролей с werkzeug.security

Санитизация имён файлов через werkzeug.utils.secure_filename

Проверка расширений файлов перед обработкой


🚀 Дальнейшее развитие

Добавить поддержку большего количества форматов
Реализовать пакетную обработку файлов
Добавить квотирование операций для пользователей
Внедрить систему восстановления пароля

⚠️ Ограничения

Режим отладки (debug=True) не должен использоваться в production
Секретный ключ (secret_key) необходимо изменить перед развёртыванием