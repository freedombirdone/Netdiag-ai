from setuptools import setup, find_packages

setup(
    name="netdiag-ai",
    version="0.1.0",
    description="LLM-assisted network troubleshooting for enterprise NOCs",
    packages=find_packages(),
    install_requires=[
        "anthropic>=0.40.0",
        "click>=8.1.0",
        "rich>=13.0.0",
        "pyyaml>=6.0",
        "python-dateutil>=2.9.0",
        "jinja2>=3.1.0",
    ],
    extras_require={
        "pcap": ["pyshark>=0.6", "scapy>=2.5"],
    },
    entry_points={
        "console_scripts": [
            "netdiag=cli:main",
        ],
    },
    python_requires=">=3.10",
)
