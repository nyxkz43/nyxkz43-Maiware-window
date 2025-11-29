# Windows Performance Diagnostic Guide

## Overview

This guide helps identify and fix Windows-specific performance bottlenecks in the malware analysis application. Instead of applying generic workarounds like timeouts or size limits, we use **verbose performance logging** to pinpoint the exact bottleneck.

## Quick Start - Diagnose Your Issue

### Option 1: Use the Diagnostic Script (Recommended)

```bash
python diagnose_windows_performance.py path\to\test_file.exe
```

This will:
- Run the full analysis with timing enabled
- Show a breakdown of time spent in each component
- Automatically identify bottlenecks (operations >20% of total time)
- Provide specific recommendations for each bottleneck

### Option 2: Manual Verbose Mode

```bash
# Set environment variable
set VERBOSE_TIMING=1

# Run analysis
python predict_single.py test_file.exe

# Or for callgraph specifically
python extract_callgraph.py binary.exe -o output --render --verbose
```

## What Was Added

### Comprehensive Timing Instrumentation

All major operations now have timing instrumentation:

**In `extract_callgraph.py`:**
- angr.Project loading
- CFG building (fast vs accurate mode)
- BFS node selection
- Subgraph creation
- DOT file writing
- Graphviz rendering (per engine)
- Total script execution

**In `predict_single.py`:**
- Model column loading
- ML feature extraction
- Feature matrix preparation
- Ensemble model execution (all 13 models)
- Majority voting
- PE section extraction
- PE import extraction
- PE string extraction
- PE type detection
- Packer detection
- File hashing for cache
- Callgraph subprocess execution
- Total prediction time

### Usage

Enable verbose timing by setting the environment variable:

```powershell
# PowerShell
$env:VERBOSE_TIMING = "1"
python predict_single.py test.exe

# Or Command Prompt
set VERBOSE_TIMING=1
python predict_single.py test.exe
```

Or use the `--verbose` flag:

```bash
python predict_single.py test.exe --verbose
python extract_callgraph.py test.exe -o output --verbose
```

## Common Windows Bottlenecks & Solutions

### 1. Subprocess Creation Overhead

**Symptom:** `callgraph subprocess execution` takes >50% of time

**Root Cause:** Windows subprocess creation is 10-100x slower than Linux

**Solutions:**
- **Cache callgraph results** (already implemented via SHA256 hash)
- **Use shell=False** to avoid cmd.exe overhead (already done)
- **Batch operations** if calling subprocess multiple times
- **Consider native Python implementation** instead of subprocess

**Implementation Example:**
```python
# Instead of subprocess per file
for file in files:
    subprocess.run(['extract_callgraph.py', file])  # Slow on Windows

# Batch process or import directly
import extract_callgraph
for file in files:
    extract_callgraph.process_file(file)  # Faster
```

### 2. angr CFG Analysis

**Symptom:** `CFG building (fast)` or `CFG building (accurate)` takes >30% of time

**Root Cause:** 
- Windows has different DLL loading behavior
- File I/O is slower on Windows
- angr's subprocess management may be inefficient

**Solutions:**
- **Use `auto_load_libs=False`** to skip library loading (already available via `--no-load-libs`)
- **Use CFGFast instead of CFGAccurate** for production
- **Add angr options** for Windows optimization:
  ```python
  proj = angr.Project(
      bin_path,
      auto_load_libs=False,
      load_debug_info=False,  # Skip debug symbols
      use_sim_procedures=True  # Use SimProcedures instead of actual libs
  )
  ```

### 3. File I/O Operations

**Symptom:** `extract_pe_strings`, `_hash_file_for_cache`, or `extract_pe_sections` taking >15% each

**Root Cause:** Reading entire large files into memory

**Windows-Specific Solutions:**
```python
# For string extraction - use memory-mapped files
import mmap

def extract_pe_strings_optimized(file_path: Path, max_strings: int = 10) -> list:
    with open(file_path, 'rb') as f:
        # Memory-mapped I/O is faster on Windows
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped:
            # Process in chunks
            chunk_size = 1024 * 1024  # 1MB chunks
            strings = []
            current = []
            
            for i in range(0, len(mmapped), chunk_size):
                chunk = mmapped[i:min(i+chunk_size, len(mmapped))]
                # Process chunk...
```

### 4. Entropy Calculation on Large Sections

**Symptom:** `extract_pe_sections` slow on large files

**Root Cause:** Computing entropy on multi-MB sections byte-by-byte

**Optimized Solution:**
```python
# Instead of processing all bytes
def entropy_fast(data: bytes, sample_size: int = 1024*1024) -> float:
    """Fast entropy calculation using sampling for large data."""
    if len(data) <= sample_size:
        return entropy(data)  # Original function for small data
    
    # Sample evenly across the data
    step = len(data) // sample_size
    sampled = data[::step][:sample_size]
    return entropy(sampled)
```

### 5. Graphviz Rendering

**Symptom:** `Graphviz rendering` takes >10% of time

**Root Cause:** subprocess.check_call blocking on Windows

**Solutions:**
- **Async rendering:** Don't block on PNG generation
- **DOT-only mode:** Generate DOT but defer PNG rendering
- **Windows PATH:** Ensure graphviz binaries are in PATH
  ```powershell
  # Add to PATH
  $env:PATH += ";C:\Program Files\Graphviz\bin"
  ```

## Diagnostic Output Example

```
[TIMING] angr.Project loading: 1.234s
[TIMING] CFG building (fast): 45.678s  ⚠️ MAJOR BOTTLENECK
[TIMING] BFS node selection: 0.123s
[TIMING] Subgraph creation: 0.045s
[TIMING] DOT file writing: 0.234s
[TIMING] Graphviz rendering with sfdp: 2.345s
[TIMING] TOTAL script execution: 49.659s

TOP BOTTLENECKS:
🔴 CFG building (fast) - 45.678s (92% of total)
   💡 Recommendation: Use --no-load-libs flag to skip DLL loading
```

## Testing Workflow

### 1. Establish Baseline

```bash
# Run on small file
python diagnose_windows_performance.py small_test.exe

# Run on medium file (10-50MB)
python diagnose_windows_performance.py medium_test.exe

# Run on large file (50MB+)
python diagnose_windows_performance.py large_test.exe
```

### 2. Identify Pattern

Look for operations that:
- Take >20% of total time consistently
- Scale poorly with file size
- Differ significantly from Linux performance

### 3. Apply Targeted Fix

Focus on the top 1-2 bottlenecks only:
- CFG building → Add angr optimizations
- Subprocess calls → Implement caching or batching
- File I/O → Use memory-mapped files or chunking
- Entropy calculation → Use sampling for large data

### 4. Measure Improvement

```bash
# Before fix
python diagnose_windows_performance.py test.exe
# Note: CFG building = 45s

# After applying fix (e.g., auto_load_libs=False)
python diagnose_windows_performance.py test.exe
# Note: CFG building = 12s  ✅ 73% improvement
```

## Windows-Specific Optimizations to Try

### 1. angr Project Loading

```python
# Current
proj = angr.Project(bin_path)

# Optimized for Windows
proj = angr.Project(
    bin_path,
    auto_load_libs=False,      # Skip DLL loading
    load_debug_info=False,     # Skip debug symbols
    use_sim_procedures=True,   # Use simulated procedures
    arch=None,                 # Let angr detect
)
```

### 2. CFG Building

```python
# Current
cfg = proj.analyses.CFGFast()

# Optimized for Windows
cfg = proj.analyses.CFGFast(
    normalize=True,              # Normalize for better performance
    force_complete_scan=False,   # Don't force exhaustive scan
    resolve_indirect_jumps=False # Skip expensive indirect jump resolution
)
```

### 3. File I/O

```python
import mmap

# For large files, use memory-mapped I/O
with open(file_path, 'rb') as f:
    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        # Read from m instead of f
        data = m[:]  # or m.read()
```

### 4. Parallel Processing (if analyzing multiple files)

```python
from multiprocessing import Pool
from pathlib import Path

def analyze_file(file_path):
    return predict_single_file(Path(file_path))

# Process files in parallel
with Pool(processes=4) as pool:
    results = pool.map(analyze_file, file_list)
```

## Comparing Windows vs Linux Performance

If you have access to both systems:

```bash
# Linux
time python predict_single.py test.exe > linux_result.json 2> linux_timing.log

# Windows  
Measure-Command { python predict_single.py test.exe > windows_result.json 2> windows_timing.log }
```

Compare the timing logs to see which specific operations differ.

## Expected Performance Characteristics

### Small Files (<5MB)
- **Total time:** 2-5 seconds
- **Main time:** ML model inference (50-70%)
- **CFG time:** <1 second

### Medium Files (5-50MB)
- **Total time:** 10-30 seconds
- **Main time:** CFG building (40-60%)
- **ML models:** (20-30%)

### Large Files (50MB+)
- **Total time:** 30-120 seconds
- **Main time:** CFG building (60-80%)
- **String extraction:** (10-20%)

## Troubleshooting

### No Timing Output

```bash
# Verify environment variable is set
echo %VERBOSE_TIMING%  # Should show: 1

# Or use --verbose flag
python predict_single.py test.exe --verbose
```

### Process Hangs

Enable verbose mode to see where it hangs:
```bash
set VERBOSE_TIMING=1
python predict_single.py test.exe
# Last timing message shows where it's stuck
```

### Incomplete CFG

If callgraph generation fails:
```bash
# Try with --no-load-libs
python extract_callgraph.py test.exe -o output --render --no-load-libs --verbose
```

## Summary

✅ **All features are preserved** - No functionality removed
✅ **Precise diagnostics** - Know exactly where time is spent
✅ **Targeted fixes** - Optimize only the actual bottlenecks
✅ **Data-driven** - Make decisions based on timing data, not assumptions

## Next Steps

1. Run `diagnose_windows_performance.py` on your problem files
2. Identify the top bottleneck from the output
3. Apply the specific optimization for that bottleneck
4. Re-test and measure improvement
5. Repeat for next bottleneck if needed

**The goal:** Make Windows performance match Linux without removing features!
