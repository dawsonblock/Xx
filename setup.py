import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

from setuptools import find_packages, setup
from setuptools.command.bdist_wheel import bdist_wheel
from setuptools.command.sdist import sdist


def require_current_manifests():
    subprocess.run(
        [sys.executable, "tools/generate_release_manifests.py", "--check"],
        check=True,
    )


class CheckedSdist(sdist):
    def run(self):
        require_current_manifests()
        super().run()

    def make_distribution(self):
        source = json.loads(Path("SOURCE_TREE_MANIFEST.json").read_text())
        generated = {
            "BUILD_MANIFEST.json",
            "IDENTITY_MANIFEST.json",
            "RELEASE_FREEZE_MANIFEST.json",
            "SOURCE_TREE_MANIFEST.json",
            "TCB_MANIFEST.json",
            "BENCHMARK_FAMILY_MANIFEST.json",
        }
        metadata = {
            "PKG-INFO",
            "SOURCES.txt",
            "dependency_links.txt",
            "top_level.txt",
            "requires.txt",
            "entry_points.txt",
        }
        self.filelist.files = [
            name
            for name in self.filelist.files
            if name in source["files"]
            or name in generated
            or (
                name.startswith("aideml_rsi.egg-info/")
                and name.rsplit("/", 1)[-1] in metadata
            )
        ]
        self.filelist.extend(sorted(source["files"]))
        self.filelist.sort()
        self.filelist.remove_duplicates()
        super().make_distribution()


class CheckedWheel(bdist_wheel):
    def run(self):
        require_current_manifests()
        super().run()


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
            Path("IDENTITY_MANIFEST.json"),
            Path("BUILD_MANIFEST.json"),
            Path("RELEASE_FREEZE_MANIFEST.json"),
            Path("SOURCE_TREE_MANIFEST.json"),
            Path("VERSION"),
            Path("BENCHMARK_FAMILY_MANIFEST.json"),
            Path("requirements-rsi-ci.in"),
            Path("requirements-rsi-ci.lock"),
            Path("requirements-runtime.lock"),
        )
        if path.is_file()
    ]
    return [("share/aideml-rsi", files)] if files else []


setup(
    name="aideml-rsi",
    version=Path("VERSION").read_text(encoding="utf-8").strip(),
    author="Weco AI",
    author_email="contact@weco.ai",
    description="AIDE with replay-based recursive self-improvement of exploration",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Wecoai/aideml",
    packages=find_packages(),
    py_modules=["rsi_anchor_service"],
    data_files=vendor_data_files() + qualification_data_files(),
    cmdclass={"sdist": CheckedSdist, "bdist_wheel": CheckedWheel},
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
    python_requires=">=3.10,<3.13",
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
