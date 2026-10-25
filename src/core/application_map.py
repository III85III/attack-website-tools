"""Bounded, redacted application relationships shared by the existing scanner."""
from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit


def origin(url):
    try:
        p = urlsplit(url)
        if p.scheme.lower() not in {'http', 'https'} or not p.hostname or p.username is not None or p.password is not None:
            return None
        return p.scheme.lower(), p.hostname.lower(), p.port or (443 if p.scheme.lower() == 'https' else 80)
    except ValueError:
        return None


def safe_url(url):
    p = urlsplit(url)
    scheme, host, port = origin(url) or ('', '', None)
    if not host:
        return ''
    host = '[' + host + ']' if ':' in host else host
    netloc = host if port == (443 if scheme == 'https' else 80) else f'{host}:{port}'
    names = sorted(set(name for name, _ in parse_qsl(p.query, keep_blank_values=True)))[:20]
    return urlunsplit((scheme, netloc, p.path or '/', urlencode([(name, '[redacted]') for name in names]), ''))


def read_only_candidate(url):
    """Conservative discovery policy; this does not assert actual application semantics."""
    if not origin(url):
        return False
    p = urlsplit(url)
    if re.search(r'(?i)(?:^|[/_.-])(logout|signout|delete|remove|reset|revoke|transfer|purchase|pay|checkout|execute|shutdown|restart|unsubscribe|activate|deactivate)(?:$|[/_.-])', p.path):
        return False
    return not any(re.search(r'(?i)password|passwd|token|secret|api.?key|cookie|authorization|session', name)
                   for name, _ in parse_qsl(p.query, keep_blank_values=True))


class ApplicationMap:
    MAX_NODES = 250
    MAX_EDGES = 500

    def __init__(self, target):
        self.target_origin = origin(target)
        self.nodes = {}
        self.edges = {}
        self.truncated = False

    def add(self, url, kind, source='', relation='references', method='GET', collected=False):
        if origin(url) != self.target_origin or self.target_origin is None:
            return None
        safe = safe_url(url)
        key = hashlib.sha256((kind + '|' + method + '|' + safe).encode()).hexdigest()[:24]
        if key not in self.nodes:
            if len(self.nodes) >= self.MAX_NODES:
                self.truncated = True
                return None
            self.nodes[key] = {'id': key, 'kind': kind, 'url': safe, 'method': method, 'collected': False}
        self.nodes[key]['collected'] |= collected
        if source and origin(source) == self.target_origin:
            edge = (safe_url(source), key, relation)
            if len(self.edges) < self.MAX_EDGES:
                self.edges[edge] = {'source_url': edge[0], 'target_id': key, 'relation': relation}
            else:
                self.truncated = True
        return key

    def snapshot(self):
        return {'nodes': sorted(self.nodes.values(), key=lambda x: x['id']),
                'relationships': [self.edges[key] for key in sorted(self.edges)],
                'truncated': self.truncated, 'node_limit': self.MAX_NODES, 'edge_limit': self.MAX_EDGES,
                'query_values_retained': False,
                'limitations': 'Discovery relationships are not runtime call graphs or proof of authorization/exploitability.'}
