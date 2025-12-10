# Symbolic execution of x86-64 binaries!

This package lifts compiled binaries or source C code into an SSA IR and uses an SMT solver to generate inputs that trigger memory safety bugs.

## Installation
```
python3 -m venv venv
source venv/bin/activate
pip install .
```

## Usage
use binary
```
symexec analyze-bytes <path_to_binary> [--frame-size FRAME_SIZE] [--debug]
```

use C source code
```
symexec analyze-source <path_to_c_file> [--frame-size FRAME_SIZE] [--cc COMPILER] [--debug]
```
