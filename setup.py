#!/usr/bin/env python
from setuptools import setup

# This file exists for compatibility with older tools
# that don't support pyproject.toml
# Modern tools will use pyproject.toml instead

_ = setup(
    name="iracing_league_session_auditor",
    version="0.1.0",
    packages=[
        "iracing_league_session_auditor",
        "iracing_league_session_auditor.modules",
    ],
    install_requires=[
        "requests>=2.26.0",
        "pandas>=1.3.0",
    ],
    entry_points={
        "console_scripts": [
            "iracing-audit=iracing_league_session_auditor.cli:main",
        ],
    },
    python_requires=">=3.8",
)
