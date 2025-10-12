#!/usr/bin/env python3
"""
Module entry point for iRacing League Session Auditor
Enables running the package as `python -m iracing_league_session_auditor`
"""
import sys
from iracing_league_session_auditor.cli import main

if __name__ == "__main__":
    sys.exit(main())
