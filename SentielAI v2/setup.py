"""
Fallback setup.py for tools that don't support pyproject.toml.
pipx install -e .  /  pip install -e .
"""
from setuptools import setup, find_packages

setup(
    name="sentinelai",
    version="2.0.0",
    description="SentinelAI — Advanced Recon Assistant",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "rich>=13.7.0",
        "prompt_toolkit>=3.0.43",
    ],
    extras_require={
        "dashboard": ["flask>=3.0"],
        "ai":        ["openai>=1.0"],
        "full":      ["flask>=3.0", "openai>=1.0"],
    },
    entry_points={
        "console_scripts": [
            "sentinelai = sentinelai.__main__:main",
        ]
    },
    package_data={"": ["*.html", "*.md", "*.json"]},
)
