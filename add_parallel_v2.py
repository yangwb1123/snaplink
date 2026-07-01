#!/usr/bin/env python3
"""
Add t.Parallel() to test functions in files that don't already have it.

Fixed version: properly handles line shifts when inserting multiple lines.
"""
import os
import re
import sys

SKIP_DIRS = {'test', 'vendor', 'node_modules'}

def should_skip_dir(path):
    parts = path.split(os.sep)
    return bool(set(parts) & SKIP_DIRS)

def find_test_files(root):
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if should_skip_dir(dirpath):
            continue
        for fn in filenames:
            if fn.endswith('_test.go'):
                files.append(os.path.join(dirpath, fn))
    return sorted(files)

def get_test_functions(content):
    """Find all top-level test functions with their positions."""
    funcs = []
    for m in re.finditer(r'^func\s+(Test\w+)\s*\([^)]*\*testing\.T[^)]*\)\s*\{', content, re.MULTILINE):
        funcs.append({
            'name': m.group(1),
            'start': m.start(),
            'end': m.end(),
            # The position of '{' is at m.end()-1
            'brace_pos': m.end() - 1,
        })
    return funcs

def needs_parallel(content, brace_pos):
    """Check if t.Parallel() is already present directly after the brace."""
    after_brace = content[brace_pos+1:]  # skip the '{'
    lines = after_brace.split('\n')
    for i in range(min(len(lines), 5)):
        line = lines[i].strip()
        if line == '' or line.startswith('//'):
            continue
        return not line.startswith('t.Parallel()')
    return True  # needs it

def process_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()
    
    funcs = get_test_functions(content)
    if not funcs:
        return 0, 0
    
    # Determine which functions need t.Parallel()
    need_parallel = [f for f in funcs if needs_parallel(content, f['brace_pos'])]
    if not need_parallel:
        return len(funcs), 0
    
    # Sort by brace_pos descending (process from end to start)
    need_parallel.sort(key=lambda f: f['brace_pos'], reverse=True)
    
    # Build the new content by inserting from end to start
    lines = content.split('\n')
    
    for func in need_parallel:
        # Find the brace line in the CURRENT (modified) content
        # Search for the function signature line
        sig_line_end = func['end']  # position of last char of signature in original
        # In original content, the signature line is the one containing this position
        orig_line_start = content.rfind('\n', 0, sig_line_end) + 1 if '\n' in content[:sig_line_end] else 0
        orig_line_end = content.find('\n', sig_line_end)
        if orig_line_end == -1:
            orig_line_end = len(content)
        sig_line_content = content[orig_line_start:orig_line_end]
        
        # Find this line in the modified content
        # The function name is unique enough
        func_name = func['name']
        
        # Find the line in the current lines list that contains this function name
        brace_idx = None
        for i, line in enumerate(lines):
            if f'func {func_name}(' in line and '*testing.T' in line:
                brace_idx = i
                break
        
        if brace_idx is None:
            print(f"  WARNING: Could not find function {func_name} in {filepath}")
            continue
        
        # Insert t.Parallel() on the next line
        indent = '\t'
        if lines[brace_idx].startswith(' '):
            leading = lines[brace_idx][:len(lines[brace_idx]) - len(lines[brace_idx].lstrip())]
            indent = leading + '\t'
        
        insert_line = brace_idx + 1
        lines.insert(insert_line, indent + 't.Parallel()')
    
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
