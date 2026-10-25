"""Lexical JS analysis with bounded statement-level taint propagation.

This is deliberately a conservative subset analyzer, not a complete JS AST or
interprocedural data-flow engine. Strings/comments are not executable sources.
No source code, candidate secret value or external URL is executed.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from urllib.parse import urljoin

from src.core.application_map import origin
from src.core.models import Finding, FindingSeverity, FindingConfidence, FindingStatus


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    line: int


def tokens(text):
    output = []
    pattern = re.compile(r'''(?P<space>\s+)|(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)|(?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)|(?P<word>[A-Za-z_$][\w$]*)|(?P<number>\d+(?:\.\d+)?)|(?P<op>=>|===|!==|==|!=|&&|\|\||\?\?|\?\.|\+=|[^\s])''')
    line = 1
    for match in pattern.finditer(text[:1_000_000]):
        kind = match.lastgroup
        value = match.group()
        if kind not in {'space', 'comment'}:
            output.append(Token(kind, value, line))
        line += value.count('\n')
        if len(output) >= 100_000:
            break
    return output


def route_literals(text, base_url):
    """Collect literal routes, excluding comments, interpolation and other origins."""
    found = {}
    for token in tokens(text):
        if token.kind != 'string' or '${' in token.value:
            continue
        value = token.value[1:-1].replace(r'\/', '/')
        if '\\' in value or len(value) > 2000 or not re.match(r'^(?:/(?:api|rest|v\d+)(?:/|\?)|https?://)', value):
            continue
        candidate = urljoin(base_url, value)
        if origin(candidate) == origin(base_url):
            found.setdefault(candidate, token.line)
        if len(found) >= 80:
            break
    return found


def _code(items):
    return ''.join(t.value for t in items if t.kind != 'string')


def analyze_flows(url, text, scan_id):
    findings = []
    variables = {}
    scopes = []
    statement = []
    seen = set()
    digest = hashlib.sha256(text.encode()).hexdigest()
    source = re.compile(r'(?:window\.)?location\.(?:search|hash|href|pathname)|document\.(?:URL|documentURI|referrer)|window\.name')

    def taint(items):
        code = _code(items)
        if re.search(r'DOMPurify\.sanitize\(|encodeURIComponent\(|encodeURI\(', code):
            return None
        direct = source.search(code)
        if direct:
            return {'source': direct.group(), 'line': next((t.line for t in items if t.kind == 'word'), 1)}
        return next((variables[t.value] for t in items if t.kind == 'word' and t.value in variables), None)

    def inspect(items):
        if not items:
            return
        # Strings preserve syntactic positions but their contents never count as code.
        values = [t.value if t.kind != 'string' else 'STRING' for t in items]
        code = ''.join(values)
        # Regex literals and dynamic template interpolation require a real parser;
        # abstain rather than interpreting pattern text as source-to-sink evidence.
        if ('/' in values and '=' in values and values.index('/') == values.index('=') + 1) or any(t.kind == 'string' and '${' in t.value for t in items):
            return
        sink = None
        expression = []
        cwe = 'CWE-79'
        for index, value in enumerate(values):
            if value == '=' and index and values[index-1] in {'innerHTML', 'outerHTML', 'href', 'location'}:
                prefix = ''.join(values[:index])
                if prefix.endswith(('.innerHTML', '.outerHTML')):
                    sink = values[index-1]
                elif re.search(r'(?:^|window\.)location(?:\.href)?$', prefix):
                    sink, cwe = 'location navigation', 'CWE-601'
                expression = items[index+1:]
            if value == '(':
                prefix = ''.join(values[:index])
                if prefix.endswith(('document.write', 'document.writeln', 'eval', 'location.assign', 'location.replace', 'window.open')):
                    sink = prefix
                    cwe = 'CWE-601' if 'location.' in prefix or prefix.endswith('window.open') else 'CWE-79'
                    expression = items[index+1:]
        observed = taint(expression) if sink else None
        if sink and observed:
            key = (cwe, items[0].line, sink, observed['source'])
            if key not in seen:
                seen.add(key)
                findings.append(Finding(scan_id=scan_id,
                    title=f'Potential client-side {"XSS" if cwe == "CWE-79" else "open redirect"} flow to {sink}',
                    description='A supported lexical source-to-sink path was observed. Execution, sanitization completeness and exploit impact were not verified. Dynamic or interprocedural flows require manual review.',
                    source_tool='Web Security Auditor', target=url, affected_component=url,
                    severity=FindingSeverity.MEDIUM, severity_source='Static untrusted input to a sensitive client-side sink; runtime impact unverified',
                    confidence=FindingConfidence.MEDIUM, confidence_justification='Statement-level lexical dependency after excluding comments and literal strings; not a complete JS parser.',
                    status=FindingStatus.POTENTIAL, cwe_id=cwe,
                    evidence_raw=__import__('json').dumps({'script_sha256': digest, 'source': observed['source'], 'source_line': observed['line'], 'sink': sink, 'sink_line': items[0].line,
                        'verification': 'static_candidate', 'source_code_retained': False}),
                    evidence_summary=f"{observed['source']} -> {sink}; line {items[0].line}; runtime verification required.",
                    remediation='Use safe DOM text APIs or vetted contextual sanitization. Restrict navigation to approved destinations. Reproduce with a harmless browser test before assigning exploit impact.'))
        # Propagate only ordinary local assignments. Reassignment kills stale taint.
        for index, value in enumerate(values):
            if value == '=' and index > 0 and items[index-1].kind == 'word' and (index == 1 or values[index-2] != '.'):
                name = values[index-1]
                dependency = taint(items[index+1:])
                if dependency:
                    variables[name] = dependency
                else:
                    variables.pop(name, None)
                break

    for token in tokens(text):
        if token.value == '{':
            # Never infer a closure/function/conditional flow across a block boundary.
            scopes.append(variables)
            variables = {}
            statement = []
        elif token.value == '}':
            inspect(statement)
            variables = scopes.pop() if scopes else {}
            statement = []
        elif token.value == ';':
            inspect(statement)
            statement = []
        else:
            # ASI is intentionally conservative: analyze newline-delimited simple statements.
            if statement and token.line > statement[-1].line and statement[-1].value not in {'=', '(', ',', '+', '.', '&&', '||'}:
                inspect(statement)
                statement = []
            statement.append(token)
    inspect(statement)
    return findings[:50]
