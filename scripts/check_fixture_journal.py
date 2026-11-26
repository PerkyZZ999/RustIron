#!/usr/bin/env python3
"""Real process lease and post-commit crash proof for an unprivileged fixture journal."""
import pathlib,tempfile,subprocess,selectors,json,argparse
ROOT=pathlib.Path(__file__).resolve().parent.parent

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--no-build',action='store_true');p.add_argument('--binary',type=pathlib.Path);args=p.parse_args()
 if not args.no_build:subprocess.run(['cargo','build','--locked','-p','rustiron-journal','--example','journal_fixture'],cwd=ROOT,check=True,stdout=subprocess.DEVNULL)
 binary=args.binary or ROOT/'target/debug/examples/journal_fixture'
 with tempfile.TemporaryDirectory(prefix='ri-journal-process-') as temp:
  directory=pathlib.Path(temp)
  def run(action,code=0):
   result=subprocess.run([binary,directory,action],capture_output=True,timeout=8);assert result.returncode==code,(action,result.returncode,result.stdout,result.stderr);assert not result.stderr;return result.stdout
  run('init');holder=subprocess.Popen([binary,directory,'hold'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  try:
   with selectors.DefaultSelector() as ready:
    ready.register(holder.stdout,selectors.EVENT_READ);assert ready.select(timeout=5),'fixture process did not become ready'
   assert holder.stdout.readline()==b'ready\n'
   assert b'writer lease refused' in run('inspect',2)
  finally:
   stdout,stderr=holder.communicate(input=b'x',timeout=5);assert holder.returncode==0 and not stderr
  run('crash',77)
  observed=run('inspect');assert b'delete 3 true false' in observed and b'Some(Intent)' in observed and b'Succeeded' not in observed
  assert b'blocks new work' in run('new',2)
  assert run('unknown')==b'NeedsAttention\n'
  assert b'blocks new work' in run('new',2)
  assert run('complete')==b'Succeeded\n'
  assert b'New(' in run('new')
 print(json.dumps({'task':'S02/W012','status':'passed','cases':['distinct_process_writer_denied','abrupt_exit_after_durable_intent_preserves_unknown_reality','restart_does_not_infer_success_or_retry','uncertain_observation_blocks_new_work','matching_target_report_releases_fixture_slot'],'limits':'reported metadata only; no host effect, real signature admission, VM power-loss or fsync fault proof'},indent=2))

if __name__=='__main__':main()
