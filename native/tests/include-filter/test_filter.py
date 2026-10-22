#!/usr/bin/env python3
"""Real JVM integration test (Linux): --agent SO --headers JDK/include.
Uses the JDK compiler module; no Gradle/Python dependencies required.
Set JAVA to run the resulting Java 8-compatible fixture on Java 21.
"""
import argparse, json, os, pathlib, subprocess, tempfile
HERE = pathlib.Path(__file__).resolve().parent

def run(*args):
    subprocess.run(list(map(str, args)), check=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--agent', required=True, type=pathlib.Path)
    parser.add_argument('--headers', required=True, type=pathlib.Path)
    args = parser.parse_args()
    java = os.environ.get('JAVA', 'java')
    compiler = os.environ.get('JAVAC_JAVA', java)
    with tempfile.TemporaryDirectory() as td:
        p = pathlib.Path(td)
        unit = p/'class_filter_test'
        run('g++', '-std=c++17', '-I'+str(HERE.parents[1]/'include'),
            HERE/'class_filter_test.cpp', '-o', unit)
        run(unit)
        print('PASS class-name and wildcard unit checks', flush=True)
        sources = {
            'obf/Selected.java': 'package obf; public class Selected { public static native void run(); public static native void inner(); }',
            'obf/Helper.java': 'package obf; public class Helper { public static void fail() { throw new IllegalStateException("fixture"); } }',
            'other/Excluded.java': 'package other; public class Excluded { public static native void run(); }',
            # "native" is a Java keyword; patch this same-length package name after compilation.
            'nativx/Selected.java': 'package nativx; public class Selected { public static native void run(); }',
            'Main.java': '''public class Main {
              public static void main(String[] a) throws Exception {
                System.load(a[0]); obf.Selected.run(); other.Excluded.run();
                Class.forName("native.Selected").getMethod("run").invoke(null);
                Thread t = new Thread(() -> obf.Selected.run()); t.start(); t.join();
              }
            }''',
        }
        for name, content in sources.items():
            f = p / name
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(content)
        run(compiler, '-m', 'jdk.compiler/com.sun.tools.javac.Main', '--release', '8', '-d', p,
            *(p / name for name in sources))
        patched = p / 'native/Selected.class'
        patched.parent.mkdir()
        patched.write_bytes((p/'nativx/Selected.class').read_bytes().replace(b'nativx', b'native'))
        fixture = p/'fixture.so'
        run('g++', '-std=c++17', '-shared', '-fPIC', '-I'+str(args.headers),
            '-I'+str(args.headers/'linux'), HERE/'fixture.cpp', '-o', fixture)
        cases = [('', False), ('include=obf.*;native.*', True),
                 ('include=obf/*;native/*', True), ('include= obf.* ; native.* ', True),
                 ('include=obf.*;native.*,log-all=true', True), ('include=missing.*', True),
                 ('include=obf.*,include=native.*', True), ('include=', False)]
        for i, (options, filtered) in enumerate(cases):
            trace = p/f'trace-{i}.jsonl'
            run(java, f'-agentpath:{args.agent.resolve()}=trace={trace},{options}', '-cp', p, 'Main', fixture)
            events = [json.loads(line) for line in trace.read_text().splitlines()]
            loaded = next(e for e in events if e['ev'] == 'agent-loaded')
            assert loaded['includeActive'] == filtered, loaded
            enters = [e for e in events if e['ev'] == 'enter']
            exits = [e for e in events if e['ev'] == 'exit']
            assert len(enters) == len(exits)
            stacks = {}
            for e in events:
                if e['ev'] in ('enter', 'exit'):
                    stack = stacks.setdefault(e['thr'], [])
                    key = (e['owner'], e['name'], e['desc'])
                    if e['ev'] == 'enter': stack.append(key)
                    else: assert stack.pop() == key, e
            assert all(not s for s in stacks.values())
            messages = [e['args'][0] for e in events if e.get('call') == 'NewStringUTF']
            if options == 'include=missing.*':
                assert not enters
                assert not any(e['ev'] in ('bind', 'jni', 'jni-init', 'exc', 'excCatch') for e in events)
            else:
                assert {'KEEP_BEFORE', 'KEEP_AFTER', 'KEEP_INNER', 'KEEP_NATIVE'} <= set(messages), messages
                if filtered:
                    assert all(not str(x).startswith('DROP_') for x in messages), messages
                    assert {e['owner'] for e in events if e['ev'] in ('enter', 'exit', 'bind')} == {'obf/Selected', 'native/Selected'}
                    assert any(e['ev']=='exc' and e['owner']=='obf/Helper' for e in events)
                else:
                    assert {'DROP_BEFORE', 'DROP_AFTER'} <= set(messages)
            print('PASS', options or '(default)')

if __name__ == '__main__': main()
