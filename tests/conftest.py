import sys
import os

# Insert root directory into sys.path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# Ensure hermetic execution for tests by default
os.environ.setdefault("CONTRACTGUARD_OFFLINE", "1")

