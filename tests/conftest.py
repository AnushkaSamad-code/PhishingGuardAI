"""Shared test setup for consistent Windows CPU detection behavior."""
import os

# loky otherwise invokes the deprecated `wmic` utility to count physical cores.
os.environ.setdefault("LOKY_MAX_CPU_COUNT", str(min(4, os.cpu_count() or 1)))
