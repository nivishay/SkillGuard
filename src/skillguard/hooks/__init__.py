"""Claude Code hook entry points that drive the gate core.

Each hook is a thin adapter: it reads the hook's stdin JSON, runs the shared gate logic
against the real skills directories and state, and writes the hook's stdout JSON. The
enforcement decisions all live in :mod:`skillguard.gate`; nothing agent-specific leaks into
the core.
"""
