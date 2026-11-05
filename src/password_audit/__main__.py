"""Allow ``python -m password_audit`` to run the CLI."""

from .cli import main

raise SystemExit(main())
