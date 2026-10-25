"""Existing JavaScript audit's bounded collection and structured evidence helpers."""
import hashlib
import json
import re
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

from src.adapters.javascript_analysis import analyze_flows, route_literals
from src.core.application_map import ApplicationMap, origin, read_only_candidate, safe_url
from src.core.models import Finding, FindingSeverity, FindingConfidence, FindingStatus
from src.core.privacy import sanitize_text


def audit_assets(adapter, base_url, script_urls, scan_id=None, progress_callback=None):
    findings = []
    adapter._collected_scripts_text = []
    adapter._discovered_endpoints = []
    graph = getattr(adapter, '_application_map', None) or ApplicationMap(base_url)
    adapter._application_map = graph
    routes = {}
    for js_url in list(dict.fromkeys(script_urls))[:8]:
        if origin(js_url) != origin(base_url):
            continue
        graph.add(js_url, 'javascript', base_url, 'loads_script')
        if progress_callback:
            progress_callback('Analyzing JavaScript routes and source-map evidence…')
        try:
            response = adapter._bounded_get(js_url, timeout=6)
            if response.status_code != 200:
                continue
            text = response.text[:1_000_000]
            if not text or text.lstrip().lower().startswith(('<!doctype html', '<html')):
                continue
            graph.add(js_url, 'javascript', collected=True)
            adapter._collected_scripts_text.append(text)
            findings.extend(analyze_flows(safe_url(js_url), text, scan_id))
            for route, line in route_literals(text, base_url).items():
                graph.add(route, 'api_route', js_url, 'javascript_literal')
                routes.setdefault(route, {'source': safe_url(js_url), 'line': line})
            # Resolve the actual reference; query strings must not precede '.map'.
            references = re.findall(r'(?m)//[#@]\s*sourceMappingURL\s*=\s*(\S+)', text)
            parsed = urlsplit(js_url)
            fallback = urlunsplit((parsed.scheme, parsed.netloc, parsed.path + '.map', '', ''))
            candidates = [urljoin(js_url, ref) for ref in references[:2]] if references else [fallback]
            for map_url in list(dict.fromkeys(candidates))[:2]:
                if origin(map_url) != origin(base_url) or not read_only_candidate(map_url):
                    continue
                graph.add(map_url, 'source_map', js_url, 'source_map_reference')
                try:
                    mapped = adapter._bounded_get(map_url, timeout=5)
                    if mapped.status_code != 200:
                        continue
                    document = json.loads(mapped.text)
                    if (not isinstance(document, dict) or type(document.get('version')) is not int or document['version'] != 3
                            or not isinstance(document.get('sources'), list) or not document['sources']
                            or not all(isinstance(name, str) for name in document['sources'])
                            or not isinstance(document.get('mappings'), str)):
                        continue
                    content = document.get('sourcesContent', [])
                    if content is not None and (not isinstance(content, list) or not all(isinstance(value, (str, type(None))) for value in content)):
                        continue
                    embedded = sum(isinstance(value, str) and bool(value) for value in (content or []))
                    graph.add(map_url, 'source_map', collected=True)
                    findings.append(Finding(scan_id=scan_id, title='Exposed JavaScript Source Map',
                        description='A complete v3 source-map JSON structure was collected. Public source maps may be intentional. Source paths and embedded source are not proof of credential exposure or exploitability.',
                        source_tool=adapter.name, tool_version=adapter.version, target=safe_url(map_url),
                        severity=FindingSeverity.LOW if embedded else FindingSeverity.INFO,
                        severity_source='Observed source-map structure; application impact unverified',
                        confidence=FindingConfidence.HIGH, confidence_justification='Parsed version, sources and mappings; response snippet matching alone is not used.',
                        status=FindingStatus.OBSERVED, cwe_id='CWE-540',
                        evidence_raw=json.dumps({'script': safe_url(js_url), 'source_map': safe_url(map_url),
                            'sha256': hashlib.sha256(mapped.text.encode()).hexdigest(), 'source_count': len(document['sources']),
                            'embedded_source_count': embedded, 'source_content_retained': False}),
                        evidence_summary=f'Valid source map; {len(document["sources"])} sources, {embedded} embedded bodies. No source content retained.',
                        remediation='Decide whether frontend source disclosure is intended; remove or restrict production maps when confidential source is embedded.'))
                except (requests.RequestException, ValueError, TypeError, RecursionError):
                    continue
            providers = (
                ('AWS Access Key ID', r'\bAKIA[A-Z0-9]{16}\b', FindingSeverity.MEDIUM),
                ('GitHub token', r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})', FindingSeverity.HIGH),
                ('Google API identifier', r'\bAIza[A-Za-z0-9_-]{35}\b', FindingSeverity.LOW),
            )
            for label, pattern, severity in providers:
                candidates = [match.group() for match in re.finditer(pattern, text)]
                candidates = [value for value in candidates if 'EXAMPLE' not in value.upper()]
                if not candidates:
                    continue
                findings.append(Finding(scan_id=scan_id, title='Potential hardcoded ' + label,
                    description='A provider-shaped value was observed in a public script. It was not submitted to any provider or tested for validity. Public identifiers and revoked/test values may be harmless; verify access and restrictions before asserting a vulnerability.',
                    source_tool=adapter.name, tool_version=adapter.version, target=safe_url(js_url),
                    severity=severity, severity_source='Credential-shaped frontend value; access and impact unverified',
                    confidence=FindingConfidence.MEDIUM, confidence_justification='Pattern evidence only; no credential validation or external requests.',
                    status=FindingStatus.POTENTIAL, cwe_id='CWE-798',
                    evidence_raw=json.dumps({'script': safe_url(js_url), 'provider': label, 'matches': len(candidates),
                        'value': '[REDACTED]', 'source_sha256': hashlib.sha256(text.encode()).hexdigest(), 'credential_tested': False}),
                    evidence_summary=f'{label}: {len(candidates)} redacted candidate(s); validity and privileges unknown.',
                    remediation='Verify intended exposure and provider restrictions. Revoke and replace only values established to be credentials, and keep private credentials server-side.'))
        except (requests.RequestException, ValueError, LookupError):
            continue
    adapter._discovered_endpoints = sorted(routes)[:80]
    if routes:
        evidence = [{'url': safe_url(url), **routes[url], 'active_review_eligible': read_only_candidate(url)} for url in sorted(routes)[:80]]
        findings.append(Finding(scan_id=scan_id, title=f'Discovered {len(evidence)} JavaScript API Routes',
            description='Literal same-origin routes were extracted from fetched scripts. References can be stale or unreachable. Discovery alone is not proof of endpoint access or an authorization flaw.',
            source_tool=adapter.name, tool_version=adapter.version, target=safe_url(base_url),
            severity=FindingSeverity.INFO, severity_source='Lexical script inventory', confidence=FindingConfidence.HIGH,
            confidence_justification='Literal URLs linked to script origin and line number; comments and dynamic interpolation excluded.',
            status=FindingStatus.OBSERVED, evidence_raw=json.dumps({'routes': evidence}),
            evidence_summary=f'{len(evidence)} route references with script/line provenance.',
            remediation='Validate route ownership and read-only semantics before active review.'))
    return findings
