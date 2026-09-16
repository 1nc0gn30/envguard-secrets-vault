#!/usr/bin/env python3
"""Setup script for envguard-secrets-vault."""

from setuptools import setup, find_packages

setup(
    name="envguard-secrets-vault",
    version="1.0.0",
    description="Zero-dependency .env security auditor, armored AES-256 secrets vault, diff analyzer, CI/CD security gate, and Model Context Protocol (MCP) server.",
    author="EnvGuard Secrets Vault Contributors",
    license="MIT",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "envguard=envguard_secrets_vault.cli:main",
        ],
    },
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)
