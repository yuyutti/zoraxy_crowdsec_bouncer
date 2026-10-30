const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function page(fetch) {
    const nodes = new Map();
    function element(tag) {
        return {
            tag, textContent: '', children: [], disabled: false, attributes: {},
            classList: {add() {}, remove() {}},
            append(...children) { this.children.push(...children); },
            replaceChildren(...children) { this.children = children; },
            setAttribute(key, value) { this.attributes[key] = value; },
            set innerHTML(_) { throw new Error('Unsafe HTML insertion'); }
        };
    }
    const document = {
        createElement: element,
        createTextNode: text => ({textContent: text}),
        getElementById(id) { if (!nodes.has(id)) nodes.set(id, element('div')); return nodes.get(id); },
        addEventListener() {}
    };
    const script = fs.readFileSync('mod/web/www/index.html', 'utf8').match(/<script>\s*('use strict';[\s\S]*?)<\/script>/)[1];
    const context = vm.createContext({document, fetch, URL});
    vm.runInContext(script, context);
    return {context, document};
}

test('Refresh waits for actual requests and restores button on failure', async () => {
    let resolveMetrics;
    const pending = new Promise(resolve => { resolveMetrics = resolve; });
    const {context, document} = page(async url => {
        if (url.endsWith('metrics')) return await pending;
        return {ok: true, json: async () => ({state: 'syncing'})};
    });
    const refresh = vm.runInContext('refreshMetrics()', context);
    const button = document.getElementById('refresh-btn');
    assert.equal(button.disabled, true);
    await Promise.resolve();
    assert.equal(button.disabled, true);
    resolveMetrics({ok: false, status: 503});
    await refresh;
    assert.equal(button.disabled, false);
    assert.match(document.getElementById('metrics-dashboard').textContent, /503/);
});

test('Headers use plain text and update links stay in the fork', async () => {
    const {context, document} = page(async url => ({ok: true, json: async () => url.endsWith('headers')
        ? {headers: {'X-Visible': ['<a&b>']}}
        : {version: 'v1.2.4-1', updateLink: 'https://attacker.invalid/payload'}}));
    await vm.runInContext('fetchHeaders()', context);
    assert.equal(document.getElementById('headers-display').textContent, 'X-Visible: <a&b>');
    await vm.runInContext('fetchVersion()', context);
    assert.equal(document.getElementById('version-info').children.length, 1);
});
