Installation Guide

Follow the steps below to install and run SentinelAI on Linux using a Python virtual environment.

1. Clone the Repository

Clone the project from GitHub:

git clone https://github.com/Maquli234/SentielAI.git
cd sentinelai
2. Create a Virtual Environment

Create an isolated Python environment to avoid dependency conflicts:

python3 -m venv venv
3. Activate the Virtual Environment

Activate it before installing dependencies.

Linux / macOS:

source venv/bin/activate

After activation your terminal should show something like:

(venv) user@machine:~/sentinelai$
4. Install Dependencies

Upgrade pip and install required packages:

pip install --upgrade pip
pip install -r requirements.txt

If the project uses editable installation for the CLI command:

pip install -e .
