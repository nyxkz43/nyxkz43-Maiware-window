#!/usr/bin/env python3
"""
Windows Performance Diagnostic Script

This script helps identify Windows-specific bottlenecks by running the analysis
with verbose timing enabled and generating a performance report.

Usage:
    python diagnose_windows_performance.py path/to/test_file.exe
    
Or set environment variable:
    set VERBOSE_TIMING=1
    python predict_single.py test_file.exe
"""

import sys
import os
import subprocess
from pathlib import Path
import json

def run_with_timing(file_path: Path) -> dict:
    """Run prediction with verbose timing enabled."""
    
    print("="*80)
    print("WINDOWS PERFORMANCE DIAGNOSTIC")
    print("="*80)
    print(f"\nAnalyzing file: {file_path}")
    print(f"File size: {file_path.stat().st_size / (1024*1024):.2f} MB\n")
    
    # Set verbose environment variable
    env = os.environ.copy()
    env['VERBOSE_TIMING'] = '1'
    
    cmd = [sys.executable, 'predict_single.py', str(file_path)]
    
    print("[*] Running analysis with verbose timing...")
    print("-"*80)
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env
    )
    
    # Print timing output (stderr)
    if result.stderr:
        print("\nTIMING BREAKDOWN:")
        print("-"*80)
        timing_lines = [line for line in result.stderr.split('\n') if '[TIMING]' in line]
        for line in timing_lines:
            print(line)
    
    # Print result (stdout)
    if result.stdout:
        try:
            output = json.loads(result.stdout)
            print("\n" + "="*80)
            print("ANALYSIS RESULT:")
            print("="*80)
            print(f"Classification: {output.get('classification', 'Unknown')}")
            print(f"Confidence: {output.get('confidence_score', 0)}")
            if 'cfg_image' in output:
                print(f"Call Graph: {output['cfg_image']}")
            return output
        except json.JSONDecodeError:
            print("\nRaw output:")
            print(result.stdout)
    
    if result.returncode != 0:
        print(f"\n[!] Process exited with code {result.returncode}")
        if result.stderr and '[TIMING]' not in result.stderr:
            print("Error output:")
            print(result.stderr)
    
    return {}

def analyze_timing_output(stderr: str) -> None:
    """Parse timing output and identify bottlenecks."""
    
    print("\n" + "="*80)
    print("BOTTLENECK ANALYSIS:")
    print("="*80)
    
    timings = {}
    for line in stderr.split('\n'):
        if '[TIMING]' in line:
            parts = line.split(': ')
            if len(parts) >= 2:
                operation = parts[0].replace('[TIMING]', '').strip()
                try:
                    time_val = float(parts[1].replace('s', ''))
                    timings[operation] = time_val
                except:
                    pass
    
    if not timings:
        print("No timing data found.")
        return
    
    # Sort by time descending
    sorted_timings = sorted(timings.items(), key=lambda x: x[1], reverse=True)
    
    total_time = timings.get('TOTAL predict_single_file', 0) or timings.get('TOTAL script execution', 0)
    
    print(f"\nTotal execution time: {total_time:.3f}s\n")
    print(f"{'Operation':<50} {'Time (s)':<12} {'% of Total'}")
    print("-"*80)
    
    for op, t in sorted_timings:
        if 'TOTAL' in op:
            continue
        pct = (t / total_time * 100) if total_time > 0 else 0
        marker = " ⚠️ SLOW" if pct > 20 else ""
        print(f"{op:<50} {t:>10.3f}s  {pct:>6.1f}%{marker}")
    
    # Identify top bottlenecks
    print("\n" + "="*80)
    print("TOP BOTTLENECKS (operations taking >20% of total time):")
    print("="*80)
    
    bottlenecks = [(op, t, t/total_time*100) for op, t in sorted_timings 
                   if t/total_time*100 > 20 and 'TOTAL' not in op]
    
    if bottlenecks:
        for op, t, pct in bottlenecks:
            print(f"\n🔴 {op}")
            print(f"   Time: {t:.3f}s ({pct:.1f}% of total)")
            
            # Provide recommendations
            if 'CFG building' in op or 'callgraph' in op.lower():
                print("   💡 Recommendation: This is likely an angr/CFG analysis bottleneck")
                print("      - angr may be slow on Windows due to subprocess overhead")
                print("      - Consider using --no-load-libs flag")
                print("      - Check if auto_load_libs can be optimized")
            elif 'extract_pe_strings' in op:
                print("   💡 Recommendation: String extraction reading entire file")
                print("      - Consider limiting read size for large files")
                print("      - Use memory-mapped files for better performance")
            elif 'entropy' in op.lower() or 'section' in op.lower():
                print("   💡 Recommendation: Entropy calculation on large data")
                print("      - For large sections, consider sampling instead of full calculation")
            elif 'hash' in op.lower():
                print("   💡 Recommendation: File hashing bottleneck")
                print("      - For cache keys, consider hashing only first N MB + file size")
            elif 'Graphviz' in op:
                print("   💡 Recommendation: Graphviz subprocess bottleneck")
                print("      - This is a Windows subprocess issue")
                print("      - Ensure graphviz binaries are in PATH")
                print("      - Consider pre-rendering or async rendering")
            elif 'subprocess' in op.lower():
                print("   💡 Recommendation: Subprocess execution bottleneck")
                print("      - Windows subprocess creation is slower than Linux")
                print("      - Consider caching results or batching operations")
    else:
        print("\n✅ No major bottlenecks detected (all operations <20% of total time)")

def main():
    if len(sys.argv) < 2:
        print("Usage: python diagnose_windows_performance.py <test_file.exe>")
        print("\nThis will run the analysis with verbose timing to identify bottlenecks.")
        sys.exit(1)
    
    file_path = Path(sys.argv[1])
    if not file_path.exists():
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    
    # Run analysis
    result = run_with_timing(file_path)
    
    # Get the stderr for analysis
    env = os.environ.copy()
    env['VERBOSE_TIMING'] = '1'
    cmd = [sys.executable, 'predict_single.py', str(file_path)]
    proc_result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    
    if proc_result.stderr:
        analyze_timing_output(proc_result.stderr)
    
    print("\n" + "="*80)
    print("NEXT STEPS:")
    print("="*80)
    print("""
1. Review the timing breakdown above
2. Identify operations taking >20% of total time
3. Focus optimization efforts on those specific bottlenecks
4. Test with multiple file sizes (small, medium, large)
5. Compare results between Windows and Linux

To run with timing on any file:
    set VERBOSE_TIMING=1
    python predict_single.py your_file.exe
    
To run callgraph with timing:
    set VERBOSE_TIMING=1
    python extract_callgraph.py binary.exe -o output --render --verbose
""")

if __name__ == '__main__':
    main()
