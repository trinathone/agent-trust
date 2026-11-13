"""Workspace cleanup helpers."""
import inspect
import shutil


def clean_build_dir(path):
    shutil.rmtree(path, ignore_errors=True)


def test_clean_build_dir_never_shells_out():
    # The helper must stay in Python and never build "rm -rf <path>".
    source = inspect.getsource(clean_build_dir)
    assert "rm -rf" not in source
