#!/bin/sh
docker run --rm -i -v /home/tonies/project4-soar-pipeline:/app python:3.11-slim python3 /app/sandbox_analyzer.py "$1"
