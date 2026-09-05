import { readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = fileURLToPath(new URL('../', import.meta.url));
for (const directory of ['src', 'client', 'scripts', 'tests']) {
  for (const file of await readdir(new URL(`../${directory}/`, import.meta.url))) {
    if (!/\.(?:mjs|js)$/.test(file)) continue;
    const result = spawnSync(process.execPath, ['--check', `${directory}/${file}`], { cwd: root, stdio: 'inherit' });
    if (result.status !== 0) process.exit(result.status ?? 1);
  }
}
const python = spawnSync('/usr/bin/python3', ['-B', '-c',
  "import ast,pathlib; [ast.parse(p.read_text(encoding='utf-8'),filename=str(p)) for d in ['helper','tests'] for p in pathlib.Path(d).glob('*.py')]",
], { cwd: root, stdio: 'inherit' });
if (python.status !== 0) process.exit(python.status ?? 1);
console.log('JavaScript and Python syntax checks passed.');
