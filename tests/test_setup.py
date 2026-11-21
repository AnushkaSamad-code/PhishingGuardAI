"""Basic checks for the Phase 1 workspace layout."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_required_directories_exist():
    for folder in ("data/raw", "data/raw/extra_email_sources", "data/processed", "models",
                   "src", "utils", "tests", "notebooks", "documentation"):
        assert (ROOT / folder).is_dir(), folder

def test_raw_sources_are_preserved():
    assert (ROOT / "data/raw/phishing_site_urls.csv").is_file()
    assert (ROOT / "data/raw/phishing_email.csv").is_file()
    for name in ("CEAS_08.csv", "Enron.csv", "Ling.csv", "Nazario.csv", "Nigerian_Fraud.csv", "SpamAssasin.csv"):
        assert (ROOT / "data/raw/extra_email_sources" / name).is_file()
