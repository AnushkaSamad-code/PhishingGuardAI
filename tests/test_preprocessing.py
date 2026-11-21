"""Tests for real-data preprocessing transformations and splits."""
import pandas as pd
from utils.preprocessing import clean_dataset, split_dataset

def test_cleaning_standardizes_labels_and_removes_bad_rows():
    source = pd.DataFrame({"URL": [" a ", "b", "b", "  ", None], "Label": ["good", "bad", "bad", "good", "bad"]})
    cleaned, stats = clean_dataset(source, "URL", "Label")
    assert cleaned.to_dict("records") == [{"text": "a", "label": 0}, {"text": "b", "label": 1}]
    assert stats["null_rows_removed"] == 1
    assert stats["whitespace_rows_removed"] == 1
    assert stats["duplicate_rows_removed"] == 1

def test_stratified_split_sizes_and_columns(tmp_path):
    data = pd.DataFrame({"text": [f"item-{i}" for i in range(100)], "label": [i % 2 for i in range(100)]})
    result = split_dataset(data, tmp_path, "text")
    assert [result[k]["rows"] for k in ("train", "val", "test")] == [70, 15, 15]
    for suffix in ("train", "val", "test"):
        saved = pd.read_csv(tmp_path / f"text_{suffix}.csv")
        assert list(saved.columns) == ["text", "label"]
        assert set(saved.label) == {0, 1}
