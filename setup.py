from collections import defaultdict
from pathlib import Path

from setuptools import find_packages, setup

with open("README.md", "r") as f:
    long_description = f.read()

with open("requirements.txt", "r") as f:
    requirements = f.read().splitlines()


def vendor_data_files():
    """Ship the complete LocalJevFabric source tree in wheel data files."""
    vendor_root = Path("vendor/LocalJevFabric-v1.5.0")
    if not vendor_root.is_dir():
        return []
    files_by_destination = defaultdict(list)
    for path in sorted(vendor_root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative_parent = path.relative_to(vendor_root).parent
        destination = (
            Path("share/aideml-rsi/vendor/LocalJevFabric-v1.5.0") / relative_parent
        )
        files_by_destination[str(destination)].append(str(path))
    return [
        (destination, files)
        for destination, files in sorted(files_by_destination.items())
    ]


def qualification_data_files():
    """Ship integrity metadata for archive and wheel-installed tooling."""
    files = [
        str(path)
        for path in (
            Path("TCB_MANIFEST.json"),
            Path("RELEASE_FREEZE_MANIFEST.json"),
            Path("SOURCE_TREE_MANIFEST.json"),
            Path("requirements-rsi-ci.in"),
            Path("requirements-rsi-ci.lock"),
        )
        if path.is_file()
    ]
    return [("share/aideml-rsi", files)] if files else []


setup(
    name="aideml-rsi",
    version="1.3.5",
    author="Weco AI",
    author_email="contact@weco.ai",
    description="AIDE with replay-based recursive self-improvement of exploration",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Wecoai/aideml",
    packages=find_packages(),
    py_modules=["rsi_anchor_service"],
    data_files=vendor_data_files() + qualification_data_files(),
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
            "aide-rsi-anchor = rsi_anchor_service:main",
            "aide-rsi-statistics = tools.qualify_canary_statistics:main",
        ],
    },
)
