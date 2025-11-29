#!/usr/bin/env python3
"""Predict a single PE file and output comprehensive JSON with features."""
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional
import pefile

from ensemble_predict_dir import (
    load_model_columns, extract_features, prepare_feature_matrix,
    run_models, DEFAULT_MODELS_DIR, DEFAULT_MODEL_COLS, DEFAULT_MODELS
)
from ensemble_vote import run_majority_voting
import pe_to_features

BASE_DIR = Path(__file__).resolve().parent
CALLGRAPH_SCRIPT = BASE_DIR / "extract_callgraph.py"
CALLGRAPH_CACHE = BASE_DIR / "tmp_cfg_cache"

# Performance logging
VERBOSE = os.environ.get('VERBOSE_TIMING', '').lower() in ('1', 'true', 'yes')
IS_WINDOWS = platform.system() == 'Windows'

def log_time(msg: str, start_time: float) -> None:
    if VERBOSE:
        elapsed = time.time() - start_time
        print(f"[TIMING] {msg}: {elapsed:.3f}s", file=sys.stderr)


def extract_pe_sections(file_path: Path) -> list:
    """Extract section names and entropy from PE file."""
    start = time.time()
    try:
        pe = pefile.PE(str(file_path), fast_load=True)
        sections = []
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            data = section.get_data() or b''
            section_entropy = pe_to_features.entropy(data)
            sections.append({
                'name': name,
                'entropy': round(section_entropy, 2),
                'size': len(data)
            })
        pe.close()
        log_time("extract_pe_sections", start)
        return sections
    except Exception as e:
        print(f"Warning: Failed to extract sections: {e}", file=sys.stderr)
        return []


def extract_pe_imports(file_path: Path) -> list:
    """Extract imported DLL and function names."""
    start = time.time()
    try:
        pe = pefile.PE(str(file_path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
        ])
        
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports[:5]:  # Limit to first 5 per DLL
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        imports.append(func_name)
        pe.close()
        log_time("extract_pe_imports", start)
        return imports[:20]  # Limit total to 20
    except Exception as e:
        print(f"Warning: Failed to extract imports: {e}", file=sys.stderr)
        return []


def extract_pe_strings(file_path: Path, max_strings: int = 10) -> list:
    """Extract interesting strings from PE file."""
    start = time.time()
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Simple string extraction (ASCII printable, min length 4)
        strings = []
        current = []
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= 4:
                    s = ''.join(current)
                    # Filter interesting strings
                    interesting_keywords = ['http', 'www', '.exe', '.dll', 'cmd', 'shell', 
                                          'download', 'install', 'registry', 'temp', 'system']
                    if any(kw in s.lower() for kw in interesting_keywords):
                        strings.append(s)
                        if len(strings) >= max_strings:
                            break
                current = []
        
        log_time("extract_pe_strings", start)
        return strings[:max_strings]
    except Exception as e:
        print(f"Warning: Failed to extract strings: {e}", file=sys.stderr)
        return []


def get_pe_type(file_path: Path) -> str:
    """Determine PE type (PE32/PE32+)."""
    try:
        pe = pefile.PE(str(file_path), fast_load=True)
        if pe.OPTIONAL_HEADER.Magic == 0x20b:
            result = 'PE64 Executable (PE32+)'
        elif pe.OPTIONAL_HEADER.Magic == 0x10b:
            result = 'PE32 Executable'
        else:
            result = 'PE Executable'
        
        # Check if it's a DLL
        if pe.FILE_HEADER.Characteristics & 0x2000:
            result = result.replace('Executable', 'DLL')
        
        pe.close()
        return result
    except Exception:
        return 'PE Executable'


def detect_packer(file_path: Path, sections: list) -> str:
    """Detect common packers based on section names and entropy."""
    try:
        # Check for high entropy sections (packed indicator)
        high_entropy_sections = [s for s in sections if s.get('entropy', 0) > 7.5]
        
        # Check for common packer section names
        section_names = [s.get('name', '').upper() for s in sections]
        
        if 'UPX0' in section_names or 'UPX1' in section_names:
            return 'UPX'
        elif '.aspack' in [s.lower() for s in section_names]:
            return 'ASPack'
        elif '.petite' in [s.lower() for s in section_names]:
            return 'Petite'
        elif len(high_entropy_sections) >= 2:
            return 'Possibly Packed (High Entropy)'
        elif len(high_entropy_sections) == 1:
            return 'Suspicious (Partial Packing)'
        else:
            return 'None Detected'
    except Exception:
        return 'Unknown'


def _hash_file_for_cache(file_path: Path) -> str:
    start = time.time()
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            if not chunk:
                break
            hasher.update(chunk)
    log_time("_hash_file_for_cache", start)
    return hasher.hexdigest()


def generate_callgraph_image(file_path: Path) -> Optional[str]:
    """Generate (or reuse cached) call graph image for the binary."""
    start = time.time()
    if not CALLGRAPH_SCRIPT.exists():
        return None

    try:
        CALLGRAPH_CACHE.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"Warning: Unable to create CFG cache directory: {exc}", file=sys.stderr)
        return None

    try:
        cache_key = _hash_file_for_cache(file_path)
    except OSError as exc:
        print(f"Warning: Unable to hash file for CFG cache: {exc}", file=sys.stderr)
        return None

    prefix = CALLGRAPH_CACHE / cache_key
    png_path = prefix.with_suffix('.callgraph.png')
    if png_path.exists():
        log_time("generate_callgraph_image (cached)", start)
        return str(png_path)

    dot_path = prefix.with_suffix('.callgraph.dot')
    
    # Pass verbose flag if enabled
    cmd = [
        sys.executable,
        str(CALLGRAPH_SCRIPT),
        str(file_path),
        '-o',
        str(prefix),
        '--render',
        '--max-nodes',
        '20',
    ]
    if VERBOSE:
        cmd.append('--verbose')
    
    # On Windows, ensure no-load-libs is used to prevent DLL loading hangs
    if IS_WINDOWS:
        cmd.append('--no-load-libs')
        if VERBOSE:
            print(f"[TIMING] Adding --no-load-libs for Windows", file=sys.stderr)

    try:
        subprocess_start = time.time()
        if VERBOSE:
            print(f"[TIMING] Starting callgraph subprocess...", file=sys.stderr)
        
        # Windows-specific subprocess flags to prevent hanging
        if IS_WINDOWS:
            # CREATE_NO_WINDOW prevents console window creation issues on Windows
            creationflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            completed = subprocess.run(
                cmd,
                cwd=str(BASE_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                creationflags=creationflags
            )
        else:
            completed = subprocess.run(
                cmd,
                cwd=str(BASE_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        log_time("callgraph subprocess execution", subprocess_start)
    except OSError as exc:
        print(f"Warning: Failed to execute callgraph helper: {exc}", file=sys.stderr)
        return None

    # Check if DOT file was generated (PNG rendering may fail if graphviz not installed)
    if os.path.exists(dot_path):
        # Prefer PNG if it exists
        if png_path.exists():
            log_time("generate_callgraph_image (generated PNG)", start)
            return str(png_path)
        else:
            # Return DOT file if PNG rendering failed
            if VERBOSE or completed.returncode != 0:
                print("Info: Callgraph DOT generated successfully. PNG not created (Graphviz may not be installed).", file=sys.stderr)
            log_time("generate_callgraph_image (generated DOT)", start)
            return str(dot_path)
    
    # Complete failure - no DOT file generated
    if completed.returncode != 0:
        msg = completed.stderr.strip() or completed.stdout.strip()
        if msg and VERBOSE:
            print(f"Warning: Callgraph generation failed: {msg}", file=sys.stderr)

    return None


def predict_single_file(file_path: Path) -> dict:
    """Predict a single file and return comprehensive result dict."""
    total_start = time.time()
    try:
        load_start = time.time()
        model_cols = load_model_columns(DEFAULT_MODEL_COLS)
        log_time("load_model_columns", load_start)
        
        # Extract features
        feat_start = time.time()
        features_df = extract_features([file_path], model_cols)
        log_time("extract_features (ML features)", feat_start)
        
        if features_df.empty:
            return {
                "error": "Failed to extract features",
                "classification": "Suspicious",
                "confidence_score": 0.5
            }
        
        matrix_start = time.time()
        feature_matrix = prepare_feature_matrix(features_df, model_cols)
        log_time("prepare_feature_matrix", matrix_start)
        
        # Run models
        models_start = time.time()
        predictions_df = run_models(feature_matrix, DEFAULT_MODELS, DEFAULT_MODELS_DIR)
        log_time("run_models (13 ensemble models)", models_start)
        
        voting_start = time.time()
        voting_df, _ = run_majority_voting(predictions_df, DEFAULT_MODELS)
        log_time("run_majority_voting", voting_start)
        
        # Get ensemble result
        row = voting_df.iloc[0]
        ensemble_class = row.get('ensemble_class', 'suspicious')
        ensemble_score = float(row.get('ensemble_score', 0.5))
        
        # Extract PE metadata
        sections = extract_pe_sections(file_path)
        imports = extract_pe_imports(file_path)
        strings = extract_pe_strings(file_path)
        
        type_start = time.time()
        file_type = get_pe_type(file_path)
        log_time("get_pe_type", type_start)
        
        packer_start = time.time()
        packer = detect_packer(file_path, sections)
        log_time("detect_packer", packer_start)
        
        # Get feature values for additional context
        feature_row = features_df.iloc[0]
        
        result = {
            "classification": ensemble_class.capitalize(),  # Benign/Suspicious/Malware
            "confidence_score": round(ensemble_score, 2),
            "votes_benign": int(row.get('votes_benign', 0)),
            "votes_malware": int(row.get('votes_malware', 0)),
            "ensemble_label": int(row.get('ensemble_label', 0)),  # 0=benign, 1=malware
            "ensemble_score": round(ensemble_score, 2),
            "ensemble_class": ensemble_class,  # benign/suspicious/malware
            "ensemble_class_id": int(row.get('ensemble_class_id', 1)),  # 0/1/2
            "file_type": file_type,
            "packer_detected": packer,
            "section_entropy": sections,
            "api_imports": imports,
            "key_strings": strings,
            "pe_features": {
                "file_size": int(feature_row.get('FileSize', 0)),
                "entropy_total": round(float(feature_row.get('Entropy_Total', 0)), 2),
                "number_of_sections": int(feature_row.get('NumberOfSections', 0)),
                "total_dlls": int(feature_row.get('Total_DLLs', 0)),
                "total_resources": int(feature_row.get('Total_Resources', 0)),
                "is_packed": int(feature_row.get('Packed', 0)) == 1
            }
        }

        cfg_image = generate_callgraph_image(file_path)
        if cfg_image:
            result["cfg_image"] = cfg_image
        
        log_time("TOTAL predict_single_file", total_start)
        return result

    except Exception as e:
        print(f"Error during prediction: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return {
            "error": str(e),
            "classification": "Suspicious",
            "confidence_score": 0.5
        }


if __name__ == '__main__':
    # Enable verbose timing if requested
    if '--verbose' in sys.argv:
        VERBOSE = True
        sys.argv.remove('--verbose')
    
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No file path provided"}))
        sys.exit(1)
    
    file_path = Path(sys.argv[1])
    if not file_path.exists():
        print(json.dumps({"error": "File not found"}))
        sys.exit(1)
    
    result = predict_single_file(file_path)
    print(json.dumps(result, indent=2))
