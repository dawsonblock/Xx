from setuptools import find_packages, setup

with open("README.md", "r") as f:
    long_description = f.read()

with open("requirements.txt", "r") as f:
    requirements = f.read().splitlines()

setup(
    name="aideml-rsi",
    version="1.3.0",
    author="Weco AI",
    author_email="contact@weco.ai",
    description="AIDE with replay-based recursive self-improvement of exploration",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Wecoai/aideml",
    packages=find_packages(),
    package_data={
        "aide": [
            "../requirements.txt",
            "utils/config.yaml",
            "utils/viz_templates/*",
            "example_tasks/bitcoin_price/*",
            "example_tasks/house_prices/*",
            "example_tasks/*",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "aide = aide.run:run",
            "aide-rsi = aide.rsi.runner:run_rsi",
            "aide-rsi-replay = aide.rsi.cli:main",
            "aide-rsi-jev = aide.rsi.jev_cli:main",
        ],
    },
)
