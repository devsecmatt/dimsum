from __future__ import annotations

import os
import sys

from alembic import context
from flask import current_app
from logging.config import fileConfig

# Add src to path so models can be imported
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

config = context.config

# Only configure file-based logging if the config file actually exists on disk
# (Flask-Migrate may resolve to a non-existent relative path inside Docker)
if config.config_file_name is not None and os.path.isfile(config.config_file_name):
    fileConfig(config.config_file_name)

# Import the Flask app to get the SQLAlchemy metadata
from dimsum.app import create_app  # noqa: E402

app = create_app()

with app.app_context():
    from dimsum.extensions import db  # noqa: E402
    import dimsum.models  # noqa: E402, F401

    target_metadata = db.metadata

    def get_url():
        return app.config["SQLALCHEMY_DATABASE_URI"]

    def run_migrations_offline():
        context.configure(
            url=get_url(),
            target_metadata=target_metadata,
            literal_binds=True,
            dialect_opts={"paramstyle": "named"},
        )
        with context.begin_transaction():
            context.run_migrations()

    def run_migrations_online():
        from sqlalchemy import engine_from_config, pool

        configuration = config.get_section(config.config_ini_section) or {}
        configuration["sqlalchemy.url"] = get_url()

        connectable = engine_from_config(
            configuration,
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
        )

        with connectable.connect() as connection:
            context.configure(connection=connection, target_metadata=target_metadata)
            with context.begin_transaction():
                context.run_migrations()

    if context.is_offline_mode():
        run_migrations_offline()
    else:
        run_migrations_online()
