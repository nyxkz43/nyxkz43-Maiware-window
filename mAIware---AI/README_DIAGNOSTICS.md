# Windows Performance Diagnostics - Quick Start

## Problem
App runs fine on Linux but has performance issues on Windows - some files don't generate callgraphs and larger files run forever.

## Solution Approach
Instead of applying workarounds, we've added **comprehensive performance logging** to identify the ACTUAL bottleneck, then fix it specifically.

---

## 🚀 Quick Start

### Diagnose a Slow File

```bash
python diagnose_windows_performance.py path\to\slow_file.exe
```

This will show you:
- ⏱️ Time spent in each operation
- 🔴 Which operations are bottlenecks (>20% of time)
- 💡 Specific recommendations for each bottleneck

### Example Output

```
============================================================
TIMING BREAKDOWN:
============================================================
[TIMING] angr.Project loading: 1.2s
[TIMING] CFG building (fast): 45.6s
[TIMING] extract_pe_sections: 0.8s
[TIMING] run_models (13 ensemble models): 2.3s
[TIMING] callgraph subprocess execution: 0.5s
[TIMING] TOTAL predict_single_file: 52.4s

============================================================
TOP BOTTLENECKS:
============================================================

🔴 CFG building (fast)
   Time: 45.6s (87% of total)
   💡 Recommendation: This is an angr/CFG analysis bottleneck
      - Use --no-load-libs flag to skip DLL loading
      - This is a Windows-specific issue with DLL loading
```

---

## 📋 What to Do Next

### 1. Run the diagnostic

```bash
# On a file that's slow or hanging
python diagnose_windows_performance.py problematic_file.exe
```

### 2. Identify the bottleneck

Look for operations taking >20% of total time in the output.

### 3. Apply the specific fix

Common bottlenecks and their fixes:

| Bottleneck | Fix |
|-----------|-----|
| **CFG building (>30% time)** | Use `--no-load-libs` flag, optimize angr settings |
| **callgraph subprocess (>20% time)** | Results are cached - ensure cache directory works |
| **extract_pe_strings (>15% time)** | Implement memory-mapped file reading |
| **File hashing (>10% time)** | Hash only first 100MB instead of entire file |
| **Graphviz rendering** | Ensure graphviz is in PATH, consider async |

### 4. Test the fix

```bash
# After applying fix, re-run diagnostic
python diagnose_windows_performance.py problematic_file.exe

# Compare before/after timing
```

---

## 💡 Common Scenarios

### Scenario 1: "CFG building takes forever"

**Symptom:** `CFG building (fast)` shows 70-95% of total time

**Solution:**
```python
# In extract_callgraph.py, modify Project creation:
proj = angr.Project(
    bin_path,
    auto_load_libs=False,  # ← Add this line
)
```

Or use the command-line flag:
```bash
python extract_callgraph.py file.exe -o output --no-load-libs --render
```

### Scenario 2: "Subprocess calls are slow"

**Symptom:** `callgraph subprocess execution` takes >20% of time

**Already Fixed:** Results are cached via SHA256 hash.
- First run: Slow (generates callgraph)
- Subsequent runs: Fast (uses cached result)

**Verify cache is working:**
```bash
# Check cache directory
dir tmp_cfg_cache
# Should contain .callgraph.png files named with SHA256 hashes
```

### Scenario 3: "String extraction hangs on large files"

**Symptom:** `extract_pe_strings` takes >15% of time on files >50MB

**Solution:** Limit read size (see WINDOWS_DIAGNOSTIC_GUIDE.md for code)

---

## 🔍 Manual Investigation

If you prefer manual investigation:

```bash
# Enable verbose timing
set VERBOSE_TIMING=1

# Run your analysis
python predict_single.py test.exe 2> timing_log.txt

# Review timing_log.txt
type timing_log.txt | findstr TIMING
```

For callgraph specifically:
```bash
python extract_callgraph.py test.exe -o output --render --verbose 2> cfg_timing.txt
```

---

## 📊 Understanding the Output

### Timing Format

```
[TIMING] operation_name: X.XXXs
```

### Bottleneck Indicators

- ⚠️ **>20% of total time** - Minor bottleneck, consider optimization
- 🔴 **>50% of total time** - Major bottleneck, should be optimized
- 🚨 **>80% of total time** - Critical bottleneck, must be fixed

### Example Analysis

```
[TIMING] TOTAL predict_single_file: 60.000s

[TIMING] load_model_columns: 0.100s          # 0.2% - OK
[TIMING] extract_features: 2.000s             # 3.3% - OK
[TIMING] run_models: 3.000s                   # 5.0% - OK
[TIMING] CFG building (fast): 52.000s         # 87% - 🚨 CRITICAL
[TIMING] extract_pe_sections: 1.500s          # 2.5% - OK
```

**Conclusion:** CFG building is the bottleneck (87% of time).

---

## 📚 Documentation

| Document | Purpose |
|----------|---------|
| `README_DIAGNOSTICS.md` | This file - Quick start guide |
| `DIAGNOSTIC_IMPLEMENTATION_SUMMARY.md` | What was implemented |
| `WINDOWS_DIAGNOSTIC_GUIDE.md` | Comprehensive troubleshooting |
| `diagnose_windows_performance.py` | Automated diagnostic tool |

---

## ✅ What's Preserved

- ✅ All malware detection features (13 ensemble models)
- ✅ Call graph generation
- ✅ Disassembly extraction
- ✅ PE analysis (sections, imports, strings)
- ✅ Packer detection
- ✅ Caching mechanism
- ✅ JSON output format

**Nothing was removed or disabled** - we're identifying the problem, not hiding it!

---

## 🎯 Next Steps

1. **Run diagnostic on your slowest file:**
   ```bash
   python diagnose_windows_performance.py your_slow_file.exe
   ```

2. **Share the timing output** if you need help interpreting it

3. **Apply the recommended fix** for the identified bottleneck

4. **Measure improvement** by re-running the diagnostic

---

## 🆘 Need Help?

If the diagnostic shows an unexpected bottleneck or you're unsure how to fix it:

1. Run the diagnostic and save output:
   ```bash
   python diagnose_windows_performance.py file.exe > diagnosis.txt 2>&1
   ```

2. Share the output showing:
   - File size
   - Top bottleneck operation and its percentage
   - Windows version
   - Python version

3. I can provide a specific optimization for that bottleneck!

---

**Remember:** We're using data-driven diagnosis to find the REAL problem, not applying generic workarounds that might reduce functionality! 🎯
