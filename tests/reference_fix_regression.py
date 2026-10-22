#!/usr/bin/env python3
"""Run without Python dependencies: python tests/reference_fix_regression.py.
J2C_JAVA may select a Java 21 executable. J2C_TEST_CLASSPATH supports source builds.
"""
import json, os, pathlib, subprocess, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
JAVA=os.environ.get('J2C_JAVA','java')
CP=os.environ.get('J2C_TEST_CLASSPATH')
def cli(main):
    return [JAVA,'-cp',CP or str(ROOT/'prebuilt/jvm/c2j-reference-tools.jar'),main]
class ReferenceFixTests(unittest.TestCase):
 def run_trace(self, events, methods=None):
    td=tempfile.TemporaryDirectory(); self.addCleanup(td.cleanup); p=pathlib.Path(td.name)
    methods=methods or [('run','()Ljava/lang/String;')]
    manifest={'schemaVersion':1,'classes':[{'name':'Test','access':1,'methods':[{'name':n,'desc':d,'access':265,'isObfuscatedNative':True} for n,d in methods]}]}
    (p/'manifest.json').write_text(json.dumps(manifest));(p/'trace.jsonl').write_text('\n'.join(json.dumps(x) for x in events)+'\n')
    r=subprocess.run(cli('j2c.tracetobc.MainKt')+['--trace',str(p/'trace.jsonl'),'--manifest',str(p/'manifest.json'),'-o',str(p/'recovered')],capture_output=True,text=True)
    out=[json.loads(f.read_text()) for f in (p/'recovered').glob('*.json')]
    return r,out,p
 def test_allocated_array_stored_for_later_uses(self):
    e=[enter()]
    e += [jni('FindClass',['java/lang/String'],'0x10'),jni('GetMethodID',['0x10','<init>','([C)V'],'0x20',memberOwner='java/lang/String',memberName='<init>',memberDesc='([C)V'),jni('NewCharArray',[2],'0x30'),jni('SetCharArrayRegion',['0x30',0,1,65]),jni('SetCharArrayRegion',['0x30',1,1,66]),jni('AllocObject',['0x10'],'0x40'),jni('CallNonvirtualVoidMethod',['0x40','0x10','0x20','0x30'],midDesc='([C)V')]
    e += [exit()];r,out,_=self.run_trace(e);self.assertEqual(r.returncode,0,r.stderr)
    ins=out[0]['instructions'];self.assertFalse(any(i['op']=='ACONST_NULL' for i in ins));self.assertEqual(sum(i['op']=='CASTORE' for i in ins),2)
 def test_external_array_parameter_bound_despite_global_symbols(self):
    desc='([C)I';e=[enter(desc=desc),jni('GetArrayLength',['0x77'],ret=2),exit(desc=desc)]
    r,out,_=self.run_trace(e,[('run',desc)]);self.assertEqual(r.returncode,0,r.stderr)
    ins=out[0]['instructions'];self.assertTrue(any(i['op']=='ALOAD' and i['var']==0 for i in ins));self.assertFalse(any(i['op']=='ACONST_NULL' for i in ins))
 def test_explicit_owner_beats_alias_name(self):
    e=[enter(desc='()I'),jni('FindClass',['LimitedLemon'],'0x10',retClassName='obf/Actual'),jni('GetStaticMethodID',['0x10','x','(II)I'],'0x20',memberOwner='obf/Actual',memberName='x',memberDesc='(II)I'),jni('CallStaticIntMethod',['0x10','0x20',2,3],1,midDesc='(II)I',memberOwner='obf/Actual',memberName='x',memberDesc='(II)I'),exit(desc='()I')]
    r,out,_=self.run_trace(e,[('run','()I')]);self.assertEqual(r.returncode,0,r.stderr)
    calls=[i for i in out[0]['instructions'] if i['op']=='INVOKESTATIC'];self.assertEqual(calls[0]['owner'],'obf/Actual')
 def test_jni_init_metadata_and_inherited_owner(self):
    lookup=jni('GetStaticMethodID',['0x10','x','(II)I'],'0x20',memberOwner='obf/Base',memberName='x',memberDesc='(II)I');lookup['ev']='jni-init'
    e=[lookup,enter(desc='()I'),jni('CallStaticIntMethod',['0x10','0x20',2,3],1,midDesc='(II)I'),exit(desc='()I')]
    r,out,_=self.run_trace(e,[('run','()I')]);self.assertEqual(r.returncode,0,r.stderr)
    self.assertTrue(any(i.get('owner')=='obf/Base' for i in out[0]['instructions']))
 def test_unknown_nonzero_reference_is_not_null(self):
    e=[enter(desc='()V'),jni('SetObjectArrayElement',['0xbeef',0,'0xdead']),exit(desc='()V')]
    r,out,p=self.run_trace(e,[('run','()V')]);self.assertEqual(r.returncode,2);self.assertEqual(out,[])
    report=json.loads((p/'recovered.report.json').read_text());self.assertEqual(report['status'],'incomplete');self.assertIn('Unresolved',report['unresolved'][0]['reason'])
 def test_pending_exception_not_wrong_athrow(self):
    e=[enter(desc='()V'),jni('FindClass',['java/lang/NullPointerException'],'0x10'),jni('ThrowNew',['0x10','message'],0),exit(desc='()V')]
    r,out,_=self.run_trace(e,[('run','()V')]);self.assertEqual(r.returncode,2);self.assertEqual(out,[]);self.assertIn('pending exception',r.stderr)
 def test_case_sensitive_method_names_survive_windows(self):
    e=[enter(name='O',desc='()V'),exit(name='O',desc='()V'),enter(name='o',desc='()V'),exit(name='o',desc='()V')]
    r,out,p=self.run_trace(e,[('O','()V'),('o','()V')]);self.assertEqual(r.returncode,0,r.stderr)
    names=[f.name.casefold() for f in (p/'recovered').glob('*.json')];self.assertEqual(len(set(names)),2)
 def test_incomplete_rebuild_does_not_write_broken_jar(self):
    import struct, zipfile
    with tempfile.TemporaryDirectory() as td:
        p=pathlib.Path(td);(p/'empty').mkdir()
        def utf(s):
            b=s.encode();return bytes([1])+struct.pack('>H',len(b))+b
        cp=utf('Guard')+bytes([7])+struct.pack('>H',1)+utf('java/lang/Object')+bytes([7])+struct.pack('>H',3)+utf('run')+utf('()V')
        data=struct.pack('>IHHH',0xcafebabe,0,65,7)+cp+struct.pack('>HHHHHHHHHHH',33,2,4,0,0,1,265,5,6,0,0)
        with zipfile.ZipFile(p/'input.jar','w') as z:z.writestr('Guard.class',data)
        r=subprocess.run(cli('j2c.classrebuilder.MainKt')+['--input',str(p/'input.jar'),'--recovered',str(p/'empty'),'-o',str(p/'bad.jar')],capture_output=True,text=True)
        self.assertEqual(r.returncode,2,r.stderr);self.assertFalse((p/'bad.jar').exists());self.assertIn('Rebuild refused',r.stderr)
 def test_output_directory_cannot_mix_stale_methods(self):
    r,out,p=self.run_trace([enter(name='run',desc='()V'),exit(name='run',desc='()V')],[('run','()V')]);self.assertEqual(r.returncode,0)
    r=subprocess.run(cli('j2c.tracetobc.MainKt')+['--trace',str(p/'trace.jsonl'),'--manifest',str(p/'manifest.json'),'-o',str(p/'recovered')],capture_output=True,text=True)
    self.assertNotEqual(r.returncode,0);self.assertIn('fresh directory',r.stderr)
 def test_local_ref_alias_keeps_array_local(self):
    e=[enter(desc='([C)I'),jni('GetArrayLength',['0x30'],2),jni('NewLocalRef',['0x30'],'0x31'),jni('GetArrayLength',['0x31'],2),exit(desc='([C)I')]
    r,out,_=self.run_trace(e,[('run','([C)I')]);self.assertEqual(r.returncode,0,r.stderr);self.assertFalse(any(i['op']=='ACONST_NULL' for i in out[0]['instructions']))
def enter(name='run',desc='()Ljava/lang/String;'):return dict(ev='enter',thr=1,owner='Test',name=name,desc=desc)
def exit(name='run',desc='()Ljava/lang/String;'):return dict(ev='exit',thr=1,owner='Test',name=name,desc=desc,exc=False)
def jni(call,args,ret=None,**extra):return dict(ev='jni',thr=1,call=call,args=args,ret=ret,**extra)
if __name__=='__main__':unittest.main(verbosity=2)
