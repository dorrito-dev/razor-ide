const pty = require('node-pty');
console.log('node-pty loaded OK, version:', require('node-pty/package.json').version);
const p = pty.spawn('cmd.exe', ['/c', 'echo HELLO_FROM_PTY && ver'], { name: 'xterm-256color', cols: 80, rows: 24, cwd: process.cwd(), env: process.env });
let buf = '';
p.onData(d => { buf += d; });
p.onExit(e => { console.log('EXIT', JSON.stringify(e)); console.log('OUTPUT>>>' + buf.replace(/\x1b\[[0-9;?]*[a-zA-Z]/g,'').trim() + '<<<'); process.exit(0); });
setTimeout(() => { console.log('TIMEOUT buf=' + JSON.stringify(buf)); process.exit(2); }, 15000);
