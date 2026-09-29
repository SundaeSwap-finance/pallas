from pathlib import Path
import subprocess,os,sys,json,hashlib
sys.set_int_max_str_digits(0)
r=Path(__file__).resolve().parents[3];out=Path(os.environ['MUSASHI_COMPARISON_OUT']).resolve();out.mkdir(parents=True,exist_ok=True)
for file in ['parameters.json','synthetic-era-history.json']:
 (out/file).write_bytes((Path(__file__).parent/'cli-integer'/file).read_bytes())
bound=1<<262143
bodies={
 'positive-inside':f'[[(builtin addInteger) (con integer {bound-1})] (con integer 0)]',
 'positive-outside-fixed':f'[[(builtin addInteger) (con integer {bound})] (con integer 0)]',
 'negative-inside':f'[[(builtin addInteger) (con integer {-bound})] (con integer 0)]',
 'negative-outside':f'[[(builtin addInteger) (con integer {-bound-1})] (con integer 0)]',
 'equality-outside':f'[(lam x [[(builtin equalsInteger) x] x]) (con integer {bound})]',
 'data-outside':f'[(builtin iData) (con integer {bound})]',
}
results=[]
for name,body in bodies.items():
 case=out/name;case.mkdir(exist_ok=True)
 source=f'(program 1.1.0 (lam ctx [(lam ignored (con unit ())) {body}]))'
 env=os.environ.copy();env['MUSASHI_EVAL_EXPORT']=str(case);env['MUSASHI_EVAL_SCRIPT']=source
 with (case/'export.txt').open('w') as f:
  res=subprocess.run(['cargo','+1.97.0','test','-p','pallas-validate','--features','phase2,unstable','--lib','export_registration_cli_comparison','--','--ignored','--nocapture'],cwd=r,env=env,stdout=f,stderr=subprocess.STDOUT)
 if res.returncode:raise SystemExit(res.returncode)
 for file in ['settings.tx.json','settings.utxos.json']:
  p=case/file;s=p.read_text().replace('Extracted original settings registration; no submission','Synthetic integer-boundary phase-two diagnostic; no submission').replace('Original captured script','Synthetic integer-boundary validator')
  p.write_text(s)
 cmd=[os.environ.get('CARDANO_CLI','cardano-cli'),'dijkstra','transaction','calculate-plutus-script-cost','offline','--start-time-utc','2026-09-07T00:00:00Z','--era-history-file',str(out/'synthetic-era-history.json'),'--utxo-file',str(case/'settings.utxos.json'),'--protocol-params-file',str(out/'parameters.json'),'--tx-file',str(case/'settings.tx.json')]
 with (case/'cli.stdout').open('w') as stdout,(case/'cli.stderr').open('w') as stderr:res=subprocess.run(cmd,stdout=stdout,stderr=stderr)
 results.append({'case':name,'pallas':json.loads((case/'pallas-result.json').read_text()),'cli_exit_code':res.returncode,'cli_result':(case/'cli.stdout').read_text().strip(),'integer_range_log':'Integer out of bounds' in (case/'cli.stderr').read_text(),'synthetic_source_sha256':hashlib.sha256(source.encode()).hexdigest()})
 print(name,results[-1]['pallas'],'CLI exit',res.returncode,flush=True)
 (out/'controls.json').write_text(json.dumps(results,indent=2)+'\n')
