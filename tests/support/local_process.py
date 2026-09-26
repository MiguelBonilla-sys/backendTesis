"""Allow posix_spawn for local service fixtures on macOS.

Forking after Network.framework initializes can crash in its child handlers.
Python-created descriptors are non-inheritable; these fixtures pass no extra
descriptors. Other platforms retain subprocess' default close_fds behavior.
"""

import subprocess
import sys
from functools import partial

run = partial(subprocess.run, close_fds=sys.platform != "darwin")
check_output = partial(subprocess.check_output, close_fds=sys.platform != "darwin")
spawn = partial(subprocess.Popen, close_fds=sys.platform != "darwin")
