#!/usr/bin/env python3
"""Add t.Parallel() to test functions in files that don't already have it.

Skips:
- test/ directory (shared ssotest state, TestMain with global BcryptCost)
- Files that already have t.Parallel() for every test function
- vendor/ directory
"""
import os
import re
import subprocess
import sys

SKIP_DIRS = {'test', 'vendor', 'node_modules'}

def should_skip_dir(path):
    parts = path.split(os.sep)
    return bool(set(parts) & SKIP_DIRS)

def find_test_files(root):
    """Find all _test.go files not in skipped directories."""
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip dirs in-place so os.walk doesn't descend into them
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if should_skip_dir(dirpath):
            continue
        for fn in filenames:
            if fn.endswith('_test.go'):
                files.append(os.path.join(dirpath, fn))
    return sorted(files)

def get_test_functions(content):
    """Find all top-level test functions and their start lines."""
    funcs = []
    for m in re.finditer(r'^func\s+(Test\w+)\s*\(.*\*testing\.T.*\)\s*\{', content, re.MULTILINE):
        funcs.append({
            'name': m.group(1),
            'start': m.start(),
            'end': m.end(),
            'line_start': content[:m.start()].count('\n') + 1,
            'brace_line': m.group(0),
        })
    return funcs

def has_parallel(content, func_start):
    """Check if t.Parallel() appears directly after the function brace."""
    after_brace = content[func_start:]
    lines = after_brace.split('\n')
    if len(lines) < 2:
        return False
    # Skip blank lines
    for i in range(1, min(len(lines), 5)):
        line = lines[i].strip()
        if line == '' or line.startswith('//'):
            continue
        return line.startswith('t.Parallel()')
    return False

def process_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()
    
    lines = content.split('\n')
    funcs = get_test_functions(content)
    
    if not funcs:
        return 0, 0
    
    # Check which functions need t.Parallel()
    need_parallel = []
    for func in funcs:
        if not has_parallel(content, func['start']):
            need_parallel.append(func)
    
    if not need_parallel:
        return len(funcs), 0
    
    # Add t.Parallel() to each function that needs it
    # Process from end to start to preserve line numbers
    modified_content = content
    
    # Find the line indices where we need to insert
    # For each function, find the line after the { line
    inserts = []
    for func in reversed(need_parallel):
        line_idx = func['line_start'] - 1  # 0-indexed
        
        # Find the line that ends with { - that's the function signature
        # Then find the next non-blank line
        # We'll insert after the { line
        
        # Lines are already split in the original content
        # Find the actual brace line index
        brace_idx = line_idx
        while brace_idx < len(lines) and not lines[brace_idx].strip().endswith('{'):
            brace_idx += 1
        
        if brace_idx >= len(lines):
            continue
        
        # Check if next non-blank line after { already has t.Parallel()
        j = brace_idx + 1
        while j < len(lines) and (lines[j].strip() == '' or lines[j].strip().startswith('//')):
            j += 1
        
        if j < len(lines) and 't.Parallel()' in lines[j]:
            continue
        
        # Insert t.Parallel() on the next line after the brace
        indent = '	'  # tab
        if lines[brace_idx].startswith(' '):
            # Use same leading whitespace as the brace line
            leading = lines[brace_idx][:len(lines[brace_idx]) - len(lines[brace_idx].lstrip())]
            indent = leading + '\t'
        
        insert_line = brace_idx + 1
        inserts.append((insert_line, indent + 't.Parallel()'))
    
    # Apply inserts from end to start
    for insert_line, line_content in reversed(inserts):
        lines.insert(insert_line, line_content)
    
    new_content = '\n'.join(lines)
    if new_content != content:
        with open(filepath, 'w') as f:
            f.write(new_content)
        return len(funcs), len(need_parallel)
    
    return len(funcs), 0

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else '.'
    files = find_test_files(root)
    
    total_funcs = 0
    total_added = 0
    modified_files = 0
    
    for filepath in files:
        func_count, added = process_file(filepath)
        total_funcs += func_count
        total_added += added
        if added > 0:
            modified_files += 1
            print(f"  +{added}/{func_count} {filepath}")
    
    print(f"\nSummary: {total_added} t.Parallel() calls added across {modified_files} files ({total_funcs} total test functions)")

if __name__ == '__main__':
    main()
