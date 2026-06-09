#!/bin/bash
cp /home/rez/projects/meridian/division_audit.py /home/rez/projects/seal/seal/division_audit.py
python3 -c "
import re

# Read cli.py
with open('/home/rez/projects/seal/seal/cli.py', 'r') as f:
    content = f.read()

# Add import
content = content.replace(
    'from seal.credential_store import CredentialStore\nfrom seal.hardware import HsmManager',
    'from seal.credential_store import CredentialStore\nfrom seal.division_audit import AuditRecord, DivisionAuditTrail\nfrom seal.hardware import HsmManager'
)

# Add docstring line
content = content.replace(
    '    seal audit                         Show audit log',
    '    seal audit                         Show audit log\n    seal audit-division                Query Division audit trail'
)

# Add the two functions before Parser builder section
old_section = '# ---------------------------------------------------------------------------\n# Parser builder\n# ---------------------------------------------------------------------------'
new_funcs = '''def _print_audit_records(records):
    if not records:
        print(\"(no audit records found)\")
        return
    print(f\"{'TIMESTAMP':<22} {'RESULT':<10} {'ISSUER':<24} {'HASH':<20} SOURCE\")
    print(\"-\" * 90)
    for rec in records:
        ts = __import__('time').strftime(\"%Y-%m-%d %H:%M:%S\", __import__('time').gmtime(rec.timestamp))
        h = rec.envelope_hash[:16] + \"...\" if len(rec.envelope_hash) > 16 else rec.envelope_hash
        print(f\"{ts:<22} {rec.result:<10} {rec.issuer:<24} {h:<20} {rec.source}\")
        if rec.reason:
            print(f\"{'':>22} {'':>10} {'':>24} {'':>20} reason: {rec.reason}\")


def _cmd_audit_division(args):
    audit_trail = __import__('seal.division_audit', fromlist=['DivisionAuditTrail']).DivisionAuditTrail()
    sub = args.audit_division_command

    if sub == \"recent\":
        records = audit_trail.query_recent(limit=getattr(args, \"limit\", 20))
        _print_audit_records(records)
        return 0
    elif sub == \"rejected\":
        after_ts = None
        if args.hours:
            after_ts = __import__('time').time() - args.hours * 3600
        records = audit_trail.query_rejected(limit=getattr(args, \"limit\", 50), after_ts=after_ts)
        _print_audit_records(records)
        return 0
    elif sub == \"summary\":
        after_ts = None
        if args.hours:
            after_ts = __import__('time').time() - args.hours * 3600
        summary = audit_trail.get_summary(after_ts=after_ts)
        print(f\"Audit summary{' (last ' + str(args.hours) + 'h)' if args.hours else ''}:\")
        print(f\"  total:  {summary['total']}\")
        for cat, count in sorted(summary.get(\"counts\", {}).items()):
            print(f\"  {cat:<12} {count}\")
        return 0
    elif sub == \"search\":
        records = audit_trail.search(query=args.search_query, limit=getattr(args, \"limit\", 20))
        _print_audit_records(records)
        return 0
    elif sub == \"hash\":
        records = audit_trail.query_by_hash(envelope_hash=args.envelope_hash)
        _print_audit_records(records)
        return 0
    elif sub == \"issuer\":
        records = audit_trail.query_by_issuer(issuer=args.issuer_name, limit=getattr(args, \"limit\", 50))
        _print_audit_records(records)
        return 0
    elif sub == \"health\":
        ok = audit_trail.health()
        if ok:
            print(\"Division audit trail: OK (Division server reachable)\")
        else:
            print(\"Division audit trail: UNAVAILABLE (cannot reach Division server)\")
            return 1
        return 0
    print(f\"error: unknown audit-division subcommand: {sub}\", file=__import__('sys').stderr)
    return 2


''' 

content = content.replace(old_section, new_funcs + old_section, 1)

# Add dispatch in main
content = content.replace(
    \"    elif args.command == 'audit':\\n        return _cmd_audit(args)\",
    \"    elif args.command == 'audit':\\n        return _cmd_audit(args)\\n    elif args.command == 'audit-division':\\n        return _cmd_audit_division(args)\"
)

# Add parser for audit-division after the audit parser
old_audit_parser = \"sub.add_parser('audit', help='show the last 20 audit entries')\"
new_audit_parser = '''sub.add_parser(\"audit\", help=\"show the last 20 audit entries\")

    p_audit_div = sub.add_parser(\"audit-division\", help=\"query the VPE verification audit trail stored in Division memory\")
    audit_div_sub = p_audit_div.add_subparsers(dest=\"audit_division_command\", required=True)
    p_recent = audit_div_sub.add_parser(\"recent\", help=\"show recent verification records\")
    p_recent.add_argument(\"--limit\", type=int, default=20, help=\"max records (1-100)\")
    p_rejected = audit_div_sub.add_parser(\"rejected\", help=\"show rejected/invalid/expired verifications\")
    p_rejected.add_argument(\"--limit\", type=int, default=50, help=\"max records (1-100)\")
    p_rejected.add_argument(\"--hours\", type=float, default=None, help=\"only records in the last N hours\")
    p_summary = audit_div_sub.add_parser(\"summary\", help=\"show verification counts by result type\")
    p_summary.add_argument(\"--hours\", type=float, default=None, help=\"only count records in the last N hours\")
    p_search = audit_div_sub.add_parser(\"search\", help=\"full-text search audit records\")
    p_search.add_argument(\"search_query\", help=\"search query string\")
    p_search.add_argument(\"--limit\", type=int, default=20, help=\"max results\")
    p_hash = audit_div_sub.add_parser(\"hash\", help=\"lookup records by envelope hash\")
    p_hash.add_argument(\"envelope_hash\", help=\"SHA-256 envelope hash\")
    p_issuer = audit_div_sub.add_parser(\"issuer\", help=\"lookup records by issuer\")
    p_issuer.add_argument(\"issuer_name\", help=\"issuer string (e.g. user:rez)\")
    p_issuer.add_argument(\"--limit\", type=int, default=50, help=\"max records\")
    audit_div_sub.add_parser(\"health\", help=\"check if Division server is reachable\")'''

# Remove quotes from the replacement to avoid shell escaping issues
content = content.replace(old_audit_parser, new_audit_parser)

with open('/home/rez/projects/seal/seal/cli.py', 'w') as f:
    f.write(content)

print('CLI updated successfully')
"