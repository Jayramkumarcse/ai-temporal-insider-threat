from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_required_directories_exist():
    required_directories = [
        ROOT / "configs",
        ROOT / "data",
        ROOT / "docs",
        ROOT / "notebooks",
        ROOT / "reports",
        ROOT / "src",
        ROOT / "tests",
        ROOT / "app",
    ]

    for directory in required_directories:
        assert directory.exists()
        assert directory.is_dir()


def test_insider_threat_package_exists():
    package = ROOT / "src" / "insider_threat"

    assert package.exists()
    assert package.is_dir()
    assert (package / "__init__.py").exists()
