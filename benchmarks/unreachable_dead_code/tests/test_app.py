"""Regression tests for clean CLI app"""
from cli.app import main
from core.clean_worker import run_job

def test_worker_run():
    res = run_job("sample_task")
    assert res["active"] is True
    assert res["job"] == "sample_task"

def test_main_cli():
    assert main("ping") == 0
