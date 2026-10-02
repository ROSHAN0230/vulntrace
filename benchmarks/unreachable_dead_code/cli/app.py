"""CLI Application Entrypoint"""
from core.clean_worker import run_job

def main(job_name: str = "default") -> int:
    """Entrypoint function invoking clean worker."""
    result = run_job(job_name)
    return 0 if result else 1

if __name__ == "__main__":
    import sys
    arg = sys.argv[1] if len(sys.argv) > 1 else "default"
    sys.exit(main(arg))
