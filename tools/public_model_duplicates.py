"""Require exact semantic review for identical public wire representations."""
from collections import defaultdict
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
OWNERS = tuple('crates/' + name + '/' for name in (
    'wire', 'models-identity', 'models-crypto', 'models-collaboration',
    'models-discovery', 'models-integration'))


def duplicate_groups(structs):
    groups = defaultdict(list)
    for key, item in structs.items():
        if (not key.startswith(OWNERS) or not item.serializable or item.has_flatten
                or item.unsupported_reason or len(item.scalar_fields) < 2):
            continue
        shape = tuple((field, re.sub(r'\s+', '', kind), re.sub(r'\s+', '', attributes))
                      for field, (kind, attributes) in item.scalar_fields.items())
        groups[shape].append(key)
    return {frozenset(owners) for owners in groups.values() if len(owners) > 1}


def review_errors(actual, reviews):
    approved = {frozenset(row['owners']) for row in reviews}
    errors = ['unreviewed duplicate public wire representations: ' + ', '.join(sorted(group))
              for group in actual - approved]
    errors += ['stale public wire representation review: ' + ', '.join(sorted(group))
               for group in approved - actual]
    for row in reviews:
        if len(row['owners']) != len(set(row['owners'])) or len(row['owners']) < 2 or len(row.get('reason', '')) < 50:
            errors.append('public wire representation review lacks exact distinct owners and purpose')
    return sorted(errors)


def check(structs):
    document = json.loads((ROOT / 'tools/public-model-shape-reviews.json').read_text(encoding='utf-8'))
    return review_errors(duplicate_groups(structs), document['reviews'])
