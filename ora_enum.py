#!/usr/bin/env python3
#Author: hamb0n-3
from __future__ import annotations

import argparse
import getpass
import json
import logging
import re
import sys
from pathlib import Path
from typing import Iterable, List, Tuple

import cx_Oracle as oradb          # or 'import oracledb as oradb'
import pandas as pd

# --- (Helper utilities and constant definitions remain largely the same) ---
# ... (rest of the helper code is here) ...
# ---

###############################################################################
# ----------------------------- Helper utilities ----------------------------- #
###############################################################################

PREFIX_ORDER = ("DBA_", "ALL_", "USER_")
CATEGORY_BASES = {
    "roles":  ("ROLE_PRIVS",),
    "sys":    ("ROLE_PRIVS", "SYS_PRIVS"),
    "obj":    ("ROLE_PRIVS", "TAB_PRIVS"),
    "col":    ("ROLE_PRIVS", "COL_PRIVS"),
    "quotas": ("TS_QUOTAS",),
    "profile":("USERS",),
    "dblinks": ("DB_LINKS",),
    "sensitive": ("TAB_COLUMNS", "SOURCE",),
}

DEFAULT_SENSITIVE_TERMS = "password,passwd,secret,key,token,ssn,pii,credit,card,cvv"

CREDS_RE = re.compile(r"""
    (?P<user>[^:/@]+)
    (?::(?P<pw>[^/@]+))?
    (?:@(?P<dsn>.+))?
    """, re.X)

HIGH_IMPACT_SYS_PRIVS = {
    "CREATE ANY PROCEDURE": "Can create a procedure in another schema with definer's rights to escalate.",
    "EXECUTE ANY PROCEDURE": "Can execute potentially vulnerable procedures (e.g., with AUTHID DEFINER).",
    "GRANT ANY ROLE": "Can grant self DBA or other powerful roles.",
    "GRANT ANY PRIVILEGE": "Can grant self any system privilege.",
    "ALTER ANY TABLE": "Can add triggers to tables owned by privileged users like SYS.",
    "BECOME USER": "Can impersonate any other user, including SYS or SYSTEM.",
    "CREATE ANY TRIGGER": "Can create triggers that fire with definer's rights on table events.",
    "SELECT ANY DICTIONARY": "Can read sensitive data dictionary views, potentially exposing weaknesses.",
}

HIGH_IMPACT_OBJ_PRIVS = {
    "UTL_FILE": ("EXECUTE", "Can read from and write to arbitrary files on the database server filesystem."),
    "DBMS_SCHEDULER": ("EXECUTE", "Can run external OS commands or scripts as the Oracle user."),
    "DBMS_BACKUP_RESTORE": ("EXECUTE", "Can execute privileged file system operations on the server."),
    "DBMS_LDAP": ("EXECUTE", "Can interact with LDAP to authenticate, exfiltrate data, or modify directories."),
}


def split_csv(raw: str | None) -> List[str]:
    return [s.strip() for s in raw.split(",")] if raw else []


def _build_like_clause(column: str, terms: List[str]) -> str:
    if not terms:
        return "1=0"
    conditions = [f"UPPER({column}) LIKE '%{term.upper()}%'" for term in terms]
    return f"({' OR '.join(conditions)})"


def parse_cred(token: str) -> Tuple[str, str | None, str | None]:
    m = CREDS_RE.fullmatch(token)
    if not m:
        raise ValueError(f"Bad credential '{token}' (need user[:pw][@dsn])")
    return m.group("user"), m.group("pw"), m.group("dsn")


def resolve_cred_lists(args) -> List[Tuple[str, str, str]]:
    triples = []
    c_list = split_csv(args.C) if args.C else ([args.c] if args.c else [])
    d_list = split_csv(args.D) if args.D else ([args.d] if args.d else [])

    if not c_list:
        logging.error("No connection details given; see --help.")
        sys.exit(1)

    for idx, tok in enumerate(c_list):
        user, pw, dsn = parse_cred(tok)
        if not pw and args.ask_pass:
            pw = getpass.getpass(f"Enter password for {user}@{dsn or '...'}: ")
        elif not pw and not args.ask_pass:
            logging.error("Password missing for '%s'. Use 'user:pw' format or provide --ask-pass.", tok)
            sys.exit(1)

        if not dsn:
            if idx >= len(d_list):
                logging.error("Missing DSN for credential '%s'", tok)
                sys.exit(1)
            dsn = d_list[idx]
        triples.append((user, pw, dsn))

    return triples


def pick_prefix(cur, wanted: Iterable[str], scope: str) -> str:
    prefixes = (scope.upper() + "_",) if scope != "auto" else PREFIX_ORDER
    for p in prefixes:
        try:
            for base in wanted:
                if base in ("USERS", "TS_QUOTAS", "DB_LINKS", "TAB_COLUMNS", "SOURCE") and p != "DBA_":
                    continue
                cur.execute(f"SELECT 1 FROM {p}{base} WHERE 1=0")
            logging.debug("Using view prefix %s", p)
            return p
        except oradb.DatabaseError as exc:
            err, = exc.args
            if err.code != 942: raise
            logging.debug("%s* views not visible", p.rstrip("_"))
    raise RuntimeError("Cannot access required dictionary views")


def analyze_for_privesc(dfs: dict[str, pd.DataFrame]):
    findings = []
    if "sys" in dfs and not dfs["sys"].empty:
        sys_privs = set(dfs["sys"]["PRIVILEGE"].str.upper())
        for priv, reason in HIGH_IMPACT_SYS_PRIVS.items():
            if priv in sys_privs:
                findings.append(f"[!] High-Impact System Privilege: {priv}\n    Reason: {reason}")

    if "obj" in dfs and not dfs["obj"].empty:
        obj_df = dfs["obj"]
        for obj, (priv, reason) in HIGH_IMPACT_OBJ_PRIVS.items():
            if not obj_df[(obj_df['TABLE_NAME'] == obj) & (obj_df['PRIVILEGE'] == priv)].empty:
                 findings.append(f"[!] High-Impact Object Grant: {priv} on {obj}\n    Reason: {reason}")

    if findings:
        logging.warning("Potential privilege escalation paths found:")
        for finding in findings:
            logging.warning(finding)


###############################################################################
# --------------------- SQL generators & File Writers ------------------------ #
# ... (This section is unchanged from the previous version) ...
###############################################################################

def build_sqls(prefix: str, categories: List[str], search_terms: List[str]) -> dict[str, str]:
    p = prefix
    sql = {}
    if "roles" in categories:
        sql["roles"] = f"SELECT * FROM {p}ROLE_PRIVS WHERE grantee = :user ORDER BY granted_role"
    if "sys" in categories:
        sql["sys"] = f"""
            SELECT privilege, admin_option, grantee AS granted_to FROM {p}SYS_PRIVS WHERE grantee = :user
            UNION ALL
            SELECT p.privilege, p.admin_option, r.grantee FROM {p}SYS_PRIVS p JOIN {p}ROLE_PRIVS r ON r.granted_role = p.grantee WHERE r.grantee = :user
            ORDER BY privilege
        """
    if "obj" in categories:
        sql["obj"] = f"""
            SELECT owner, table_name, privilege, grantable, grantor, grantee FROM {p}TAB_PRIVS WHERE grantee = :user
            UNION ALL
            SELECT t.owner, t.table_name, t.privilege, t.grantable, t.grantor, r.grantee FROM {p}TAB_PRIVS t JOIN {p}ROLE_PRIVS r ON r.granted_role = t.grantee WHERE r.grantee = :user
            ORDER BY owner, table_name, privilege
        """
    if "col" in categories:
        sql["col"] = f"""
            SELECT owner, table_name, column_name, privilege, grantable, grantor, grantee FROM {p}COL_PRIVS WHERE grantee = :user
            UNION ALL
            SELECT c.owner, c.table_name, c.column_name, c.privilege, c.grantable, c.grantor, r.grantee FROM {p}COL_PRIVS c JOIN {p}ROLE_PRIVS r ON r.granted_role = c.grantee WHERE r.grantee = :user
            ORDER BY owner, table_name, column_name, privilege
        """
    if "profile" in categories:
        sql["profile"] = "SELECT * FROM dba_users WHERE username = :user"
    if "quotas" in categories:
        sql["quotas"] = "SELECT * FROM dba_ts_quotas WHERE username = :user"
    if "dblinks" in categories:
        sql["dblinks"] = "SELECT owner, db_link, username, host, created FROM dba_db_links"
    if "sensitive" in categories:
        sensitive_cols_clause = _build_like_clause('column_name', search_terms)
        sql["sensitive_columns"] = f"""
            SELECT owner, table_name, column_name FROM dba_tab_columns
            WHERE {sensitive_cols_clause}
              AND owner NOT IN ('SYS', 'SYSTEM', 'ORDSYS', 'MDSYS', 'CTXSYS', 'XDB', 'DBSNMP')
            ORDER BY owner, table_name
        """
        sensitive_source_clause = _build_like_clause('text', search_terms)
        sql["sensitive_source"] = f"""
            SELECT owner, name, type, line, text FROM dba_source
            WHERE {sensitive_source_clause}
              AND owner NOT IN ('SYS', 'SYSTEM', 'ORDSYS', 'MDSYS', 'CTXSYS', 'XDB', 'DBSNMP')
            ORDER BY owner, name, line
        """
    return sql

def fetch_frames(cur, stmts: dict[str, str], user: str) -> dict[str, pd.DataFrame]:
    dfs = {}
    for name, sql in stmts.items():
        logging.debug("Running %s query for %s", name, user)
        bind_vars = {'user': user} if ':user' in sql else {}
        try:
            cur.execute(sql, bind_vars)
            dfs[name] = pd.DataFrame(cur.fetchall(), columns=[d[0] for d in cur.description])
        except oradb.DatabaseError as exc:
            logging.warning("Failed to run query for '%s': %s", name, exc)
            dfs[name] = pd.DataFrame() # Return empty dataframe on error
    return dfs

def write_excel(dfs, path: Path):
    with pd.ExcelWriter(path) as xl:
        for name, df in dfs.items():
            if not df.empty:
                df.to_excel(xl, sheet_name=name[:31], index=False)

def write_csvs(dfs, stem: str, outdir: Path):
    for name, df in dfs.items():
        if not df.empty:
            df.to_csv(outdir / f"{stem}_{name}.csv", index=False)

def write_json(dfs, path: Path):
    merged = {k: df.to_dict(orient="records") for k, df in dfs.items() if not df.empty}
    path.write_text(json.dumps(merged, indent=2, default=str), encoding="utf-8")

def dump_outputs(dfs, stem: str, outdir: Path, formats: Iterable[str]):
    outdir.mkdir(parents=True, exist_ok=True)
    if "excel" in formats:
        write_excel(dfs, outdir / f"{stem}.xlsx")
    if "csv" in formats:
        write_csvs(dfs, stem, outdir)
    if "json" in formats:
        write_json(dfs, outdir / f"{stem}.json")

###############################################################################
# ----------------------- Main Logic Controllers ----------------------------- #
###############################################################################

def handle_direct_query(args):
    """Connects and runs a single query, printing results to stdout."""
    creds = resolve_cred_lists(args)
    query = args.query.strip()

    is_select = query.upper().startswith('SELECT')
    if not is_select and not args.force:
        logging.error("Query does not start with SELECT. Use --force to run DML/DDL statements.")
        sys.exit(1)

    for user, pw, dsn in creds:
        print(f"\n---[ Executing query on {user}@{dsn} ]---")
        try:
            conn = oradb.connect(user, pw, dsn)
            cur = conn.cursor()
            cur.execute(query)

            if cur.description: # This is True for SELECT statements
                df = pd.DataFrame(cur.fetchall(), columns=[d[0] for d in cur.description])
                if df.empty:
                    print("(Query returned no rows)")
                else:
                    print(df.to_string())
            else: # This is for DML/DDL
                logging.info("Query executed successfully. %d rows affected.", cur.rowcount)
                if not is_select:
                    conn.commit()
                    logging.info("Transaction committed.")
            cur.close()
            conn.close()
        except oradb.DatabaseError as exc:
            err, = exc.args
            logging.error("Query failed: %s (Code: %s)", err.message.strip(), err.code)
        except Exception as exc:
            logging.error("A critical error occurred: %s", exc)


def process_connection(login_user: str, pw: str, dsn: str,
                       targets: List[str], scope: str,
                       categories: List[str], formats: List[str],
                       outdir: Path, grant_flag: bool, search_terms: List[str]):
    """Main enumeration logic for a single connection."""
    logging.info("Connect %s@%s", login_user, dsn)
    conn = oradb.connect(login_user, pw, dsn)
    cur = conn.cursor()

    if grant_flag:
        # Implementation for grant_catalog_role would go here
        pass

    needed = {b for cat in categories for b in CATEGORY_BASES.get(cat, [])}
    prefix  = pick_prefix(cur, needed, scope)

    for tgt in targets or [login_user]:
        tgt_up = tgt.upper()
        logging.info("--- Enumerating Privileges for Target: %s ---", tgt_up)
        sqls = build_sqls(prefix, categories, search_terms)
        dfs  = fetch_frames(cur, sqls, tgt_up)

        analyze_for_privesc(dfs)

        stem = f"{tgt_up}_{dsn.replace(':', '-').replace('/', '_').replace('@', '_')}"
        dump_outputs(dfs, stem, outdir, formats)

    cur.close()
    conn.close()

###############################################################################
# ---------------------------- CLI & main driver ---------------------------- #
###############################################################################

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Advanced Oracle Enumerator and Query Tool for Red Teams.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    # Group for all modes
    cred_group = p.add_argument_group("Credential & Connection (All Modes)")
    cred_group.add_argument("-C", metavar="list", help="Comma-separated list: user[:pw][@dsn],...")
    cred_group.add_argument("-c", metavar="pair", help="Single credential: user[:pw]")
    cred_group.add_argument("-D", metavar="list", help="Comma-separated DSN list (for -C items w/o @dsn)")
    cred_group.add_argument("-d", metavar="dsn", help="Single DSN (for -c w/o @dsn)")
    cred_group.add_argument("-P", "--ask-pass", action="store_true", help="Prompt for passwords interactively.")

    # Group for standard enumeration mode
    enum_group = p.add_argument_group("Enumeration Mode")
    enum_group.add_argument("-T", metavar="list", help="Comma-separated list of target users to enumerate")
    enum_group.add_argument("-t", metavar="name", help="Single target user to enumerate")
    enum_group.add_argument("-s", "--scope", choices=("dba", "all", "user", "auto"), default="auto",
                            help="View prefix to use (DBA_, ALL_, USER_). Default: auto")
    enum_group.add_argument("-k", "--include", default="roles,sys,obj",
                            help="Categories to check (comma-separated):\n"
                                 "  roles, sys, obj, col, quotas, profile,\n"
                                 "  dblinks, sensitive (default: roles,sys,obj)")
    enum_group.add_argument("--search-terms", default=DEFAULT_SENSITIVE_TERMS,
                            help="Keywords for 'sensitive' search (comma-separated).\n"
                                 f"Default: {DEFAULT_SENSITIVE_TERMS}")
    enum_group.add_argument("-g", "--grant-catalog-role", action="store_true",
                            help="Attempt to grant SELECT_CATALOG_ROLE to login user (AUDITED!)")
    enum_group.add_argument("-o", "--output", default="excel", help="Formats: excel,csv,json (default: excel)")
    enum_group.add_argument("-O", "--outdir", default=".", help="Directory for result files (default: .)")

    # Group for direct query mode
    query_group = p.add_argument_group("Direct Query Mode")
    query_group.add_argument("-q", "--query", metavar="SQL", help="Execute a single query and print results to stdout.")
    query_group.add_argument("--force", action="store_true", help="Allow non-SELECT queries with -q (DANGEROUS).")

    p.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug logging")
    return p


def main(argv: List[str] | None = None):
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)-.1s: %(message)s")

    # --- Mode Dispatcher ---
    if args.query:
        handle_direct_query(args)
        sys.exit(0)
    # --- End Mode Dispatcher ---


    # Default to enumeration mode if --query is not used
    creds = resolve_cred_lists(args)
    targets = split_csv(args.T) if args.T else ([args.t] if args.t else [])
    cats    = split_csv(args.include.lower())
    fmts    = split_csv(args.output.lower())
    search_terms = split_csv(args.search_terms.lower())
    outdir  = Path(args.outdir)

    for user, pw, dsn in creds:
        try:
            process_connection(user, pw, dsn,
                               targets, args.scope.lower(),
                               cats, fmts, outdir,
                               args.grant_catalog_role, search_terms)
        except oradb.DatabaseError as exc:
            err, = exc.args
            logging.error("Oracle DB error for %s@%s: %s (Code: %s)", user, dsn, err.message.strip(), err.code)
        except Exception as exc:
            logging.error("Critical failure for %s@%s: %s", user, dsn, exc, exc_info=args.verbose)


if __name__ == "__main__":
    main()