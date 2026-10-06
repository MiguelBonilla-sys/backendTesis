// Exercise the frozen frontend OriginCard with synthetic hostile headers.
// Dependencies are resolved from the existing frontend pnpm installation.
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const { execFileSync } = require('node:child_process');
const [frozenFrontend, dependencyFrontend, output] = process.argv.slice(2).map(p => path.resolve(p));
const requireFrontend = createRequire(path.join(dependencyFrontend, 'package.json'));
const esbuild = requireFrontend('esbuild');
const component = path.join(frozenFrontend, 'src/components/IncidentInsights/IncidentInsights.tsx');
const temporary = path.join(require('node:os').tmpdir(), `t33-header-render-${process.pid}.cjs`);
const payload = '<img src=x onerror="alert(33)"><script>alert(33)</script>';
const source = `
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { OriginCard } from ${JSON.stringify(component)};
const value = ${JSON.stringify(payload)};
const html = renderToStaticMarkup(React.createElement(OriginCard, {incident: {origin: {
  header_source: 'outlook-addin', message_id: value, headers: [['From', value]],
  country: value, isp: value, ip: '8.8.8.8'
}}}));
console.log(JSON.stringify({html, payload: value, react: React.version,
  escaped: html.includes('&lt;img') && html.includes('&lt;script'),
  active_tags: /<(img|script|svg)\\b/i.test(html)}, null, 2));
`;
try {
  esbuild.buildSync({stdin: {contents: source, resolveDir: dependencyFrontend, loader: 'tsx'},
    bundle: true, platform: 'node', format: 'cjs', jsx: 'automatic', outfile: temporary,
    nodePaths: [path.join(dependencyFrontend, 'node_modules')], logLevel: 'silent'});
  fs.writeFileSync(output, execFileSync(process.execPath, [temporary]));
} finally {
  if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
}
