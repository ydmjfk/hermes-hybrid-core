#!/usr/bin/env bash
set -e

echo "===================================================================="
echo "👑 Hermes Hybrid Agent — One-Click Auto Installer"
echo "===================================================================="

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.10+ first."
    exit 1
fi

echo "📦 Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "📥 Installing verified dependencies from requirements.lock..."
pip install --upgrade pip
if [ -f "requirements.lock" ]; then
    pip install -r requirements.lock
else
    pip install -r requirements.txt
fi

if [ ! -f "config.yaml" ]; then
    echo "⚙️ Initializing config.yaml from template..."
    cp config.example.yaml config.yaml
fi

if [ ! -f ".env" ]; then
    echo "🔑 Initializing .env from template..."
    cp .env.example .env
fi

echo "🧪 Running Verification Suites..."
python3 capabilities/verify_all_capabilities.py
python3 -m unittest discover tests/

echo "===================================================================="
echo "🎉 Installation Complete! Hermes Hybrid Core is ready to use."
echo "👉 To activate environment: source venv/bin/activate"
echo "===================================================================="
