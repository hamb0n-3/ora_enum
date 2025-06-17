Of course. Here is a comprehensive `README.md` file for the script, formatted in Markdown for easy use on platforms like GitHub.

---

# `ora_privs`: Advanced Oracle Enumerator for Red Teams

`ora_privs` is a powerful, highly-configurable Python script designed for penetration testers and red teamers to rapidly enumerate privileges and discover sensitive data within Oracle databases. It automates common post-exploitation tasks, provides actionable analysis of privileges, and includes a direct query mode for surgical data extraction.

This tool helps answer critical questions during an assessment:
- What can this user see and do?
- Are there clear paths to escalate privileges?
- Where is the sensitive data (PII, credentials, keys)?
- Can I pivot to other databases?

## Features

- **Multi-Target Enumeration**: Scan multiple databases and/or user accounts with a single command.
- **Flexible Credential Handling**: Provide credentials on the command line or use an interactive prompt for better OPSEC.
- **Smart Scoping**: Automatically uses the best available data dictionary views (`DBA_`, `ALL_`, `USER_`) based on the current user's permissions.
- **Comprehensive Enumeration Categories**:
  - `roles`: Assigned roles.
  - `sys`: System-level privileges (`CREATE ANY TABLE`, etc.).
  - `obj`: Object-level privileges (`SELECT` on `payroll`, etc.).
  - `col`: Column-level privileges.
  - `profile`: User profile details, status, and password policy.
  - `quotas`: Tablespace quotas.
  - `dblinks`: Database links, a key vector for lateral movement.
- **Actionable Privilege Analysis**: Automatically identifies and flags high-impact privileges that can lead to privilege escalation (e.g., `CREATE ANY PROCEDURE`, `GRANT ANY ROLE`).
- **Configurable Sensitive Data Hunting**:
  - A dedicated `sensitive` category to find PII, credentials, API keys, etc.
  - Searches for keywords in both table/column names and PL/SQL source code.
  - Fully configurable search terms (`--search-terms`).
- **Direct Query Mode**: Execute arbitrary SQL queries directly from the command line for targeted data gathering.
- **Multiple Output Formats**: Generate reports in `Excel`, `CSV`, or `JSON` for easy analysis and integration with other tools.
- **OPSEC-Aware Features**:
  - Warns the operator before performing potentially audited actions (`--grant-catalog-role`).
  - Supports interactive password prompts to avoid shell history exposure.

## Requirements

- **Python 3.6+**
- The **`oracledb`** or **`cx_Oracle`** Python package. `oracledb` is the modern, recommended driver.
  ```bash
  pip install oracledb pandas openpyxl
  ```
- **Oracle Instant Client**: If using the Thick mode of `oracledb` or `cx_Oracle`, the Oracle Instant Client libraries must be installed and accessible.

## Usage

The script operates in two main modes: **Enumeration Mode** (default) and **Direct Query Mode** (`-q`/`--query`).

```
usage: ora_privs.py [-h] [-C list] [-c pair] [-D list] [-d dsn] [-P] [-T list] [-t name] [-s {dba,all,user,auto}] [-k include] [--search-terms SEARCH_TERMS] [-g] [-o output] [-O outdir] [-q SQL] [--force] [-v]

Advanced Oracle Enumerator and Query Tool for Red Teams.

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Enable verbose/debug logging

Credential & Connection (All Modes):
  -C list               Comma-separated list: user[:pw][@dsn],...
  -c pair               Single credential: user[:pw]
  -D list               Comma-separated DSN list (for -C items w/o @dsn)
  -d dsn                Single DSN (for -c w/o @dsn)
  -P, --ask-pass        Prompt for passwords interactively.

Enumeration Mode:
  -T list               Comma-separated list of target users to enumerate
  -t name               Single target user to enumerate
  -s {dba,all,user,auto}, --scope {dba,all,user,auto}
                        View prefix to use (DBA_, ALL_, USER_). Default: auto
  -k include, --include include
                        Categories to check (comma-separated):
                          roles, sys, obj, col, quotas, profile,
                          dblinks, sensitive (default: roles,sys,obj)
  --search-terms SEARCH_TERMS
                        Keywords for 'sensitive' search (comma-separated).
                        Default: password,passwd,secret,key,token,ssn,pii,credit,card,cvv
  -g, --grant-catalog-role
                        Attempt to grant SELECT_CATALOG_ROLE to login user (AUDITED!)
  -o output, --output output
                        Formats: excel,csv,json (default: excel)
  -O outdir, --outdir outdir
                        Directory for result files (default: .)

Direct Query Mode:
  -q SQL, --query SQL   Execute a single query and print results to stdout.
  --force               Allow non-SELECT queries with -q (DANGEROUS).

```

### DSN (Data Source Name) Format

A DSN string tells the Oracle client how to connect. Common formats include:
- **Easy Connect**: `hostname:port/service_name` (e.g., `db.example.com:1521/ORCLPDB1`)
- **TNS Name**: A name defined in your `tnsnames.ora` file (e.g., `PRODDB`)

---

### Examples

#### 1. Basic Privilege Enumeration
Enumerate the privileges of the logged-in user (`scott`) and save the results to an Excel file.

```bash
python3 ora_privs.py -c scott:tiger -d db.example.com:1521/ORCL
```
*This will create a file named `SCOTT_ORCL.xlsx` with sheets for roles, system privileges, and object privileges.*

#### 2. Multi-Target Scan with Interactive Password
Scan two different databases using different credentials. Prompt for passwords to avoid leaving them in shell history.

```bash
python3 ora_privs.py -C "hr@db1.example.com/HRDB,sys@db2.example.com/FINDB as sysdba" -P
```
*The script will prompt for the password for `hr` and then for `sys`.*

#### 3. Full Enumeration of a Specific Target User
Log in as `system` and enumerate all privilege and data categories for the `WEB_APP` user.

```bash
python3 ora_privs.py -c system -d db.example.com:1521/ORCL -P \
  -t WEB_APP \
  -k all \
  -o json -O /tmp/audit_results
```
*This command uses `-k all` as a shorthand for all categories and saves a JSON report.*

#### 4. Hunting for Sensitive Data
Log in as a low-privilege user and hunt for any columns or source code containing PII or credentials, using custom search terms.

```bash
python3 ora_privs.py -c appuser:password123 -d appdb:1521/APP \
  -k sensitive \
  --search-terms "ssn,dob,api_key,secret,auth_token"
```
*This will create an Excel file with sheets `sensitive_columns` and `sensitive_source` listing any findings.*

#### 5. Using Direct Query Mode to Get Database Version
Quickly get the database version from multiple targets.

```bash
python3 ora_privs.py -C "user1@db1,user2@db2" -D "host1/svc1,host2/svc2" -P \
  -q "SELECT banner FROM v\$version"
```
*The results will be printed directly to the console in a table format for each target.*

#### 6. Using Direct Query Mode to Add a User (OPSEC Risk!)
Create a new user. This requires the `--force` flag because it's not a `SELECT` statement.

```bash
python3 ora_privs.py -c sys:SuperSecret1@db.example.com/SYSDB as sysdba --force \
  -q "CREATE USER rteam IDENTIFIED BY P@ssword123"
```
* **WARNING**: DDL/DML statements are highly likely to be audited. Use with extreme caution.

## License

This tool is provided for educational and authorized security testing purposes only. Use of this tool for illegal or unauthorized activities is strictly prohibited. The author is not responsible for any misuse or damage caused by this tool.
