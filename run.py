#!/usr/bin/env python3
# coding: utf-8
"""see entry point: python3 run.py"""
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, 'server'))

from app import app, cfg, start_background  # noqa: E402

if __name__ == '__main__':
    start_background()
    app.run(host='0.0.0.0', port=cfg['port'], debug=False, threaded=True)
