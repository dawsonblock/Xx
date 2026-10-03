#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo '== AnyJev =='
(cd "$ROOT/components/AnyJev" && python -m pytest -q)

echo '== LocalJevFabric =='
(cd "$ROOT/fabric" && python -m pytest -q)

echo '== LLM2Jev syntax =='
python -m compileall -q "$ROOT/components/LLM2Jev/src"

echo '== jev-gateway TypeScript syntax =='
if command -v node >/dev/null 2>&1 && command -v tsc >/dev/null 2>&1; then
  node - "$ROOT/components/jev-gateway" <<'NODE'
const fs=require('fs'), path=require('path'), cp=require('child_process');
const tsc=cp.execFileSync('readlink',['-f',cp.execFileSync('which',['tsc'],{encoding:'utf8'}).trim()],{encoding:'utf8'}).trim();
const ts=require(path.join(path.dirname(path.dirname(tsc)),'lib','typescript.js'));
const root=process.argv[2]; let bad=0,count=0;
function walk(d){for(const e of fs.readdirSync(d,{withFileTypes:true})){const p=path.join(d,e.name);if(e.isDirectory()&&!['node_modules','dist'].includes(e.name))walk(p);else if(e.isFile()&&/\.tsx?$/.test(e.name)){count++;const r=ts.transpileModule(fs.readFileSync(p,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext},reportDiagnostics:true,fileName:p});for(const x of r.diagnostics||[])if(x.category===ts.DiagnosticCategory.Error){bad++;console.error(p+': '+ts.flattenDiagnosticMessageText(x.messageText,'\n'));}}}}
walk(root); console.log(`parsed ${count} TypeScript files; errors=${bad}`); if(bad)process.exit(1);
NODE
else
  echo 'node/tsc unavailable: skipped TypeScript parse check'
fi

echo 'Verification complete.'
