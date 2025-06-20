# `ora_enum`: Advanced Oracle Enumerator & Sprayer for Red Teams

`ora_enum` is a powerful, multi-modal Python script designed for penetration testers and red teamers to rapidly enumerate privileges, discover sensitive data, spray credentials, and execute direct queries within Oracle databases.

This tool helps answer critical questions during an assessment:
- **(Spray)** Which default or weak credentials are valid?
- **(Enumerate)** What can this user see and do? Are there clear paths to escalate privileges?
- **(Hunt)** Where is the sensitive data (PII, credentials, keys) or interesting database links?
- **(Query)** Can I surgically extract specific information or explore the database manually?

## Features

- **Multiple Modes of Operation**:
  - **Enumeration Mode**: Deeply audits a user's permissions, lists accessible schemas/tables, and finds sensitive data.
  - **Password Spraying Mode**: Efficiently tests lists of usernames and passwords against multiple databases.
  - **Direct Query Mode**: Executes a single SQL query for targeted data gathering.
  - **Interactive SQL Shell**: Drops into a fully interactive SQL client for a specific database connection, perfect for manual exploration.
- **Flexible Credential & Target Handling**: Provide credentials and DSNs individually, as comma-separated lists, or from files. This makes managing large-scale operations simple and scriptable.
- **Privileged Connection Support**: Use the `--as-sysdba` flag to connect with `SYSDBA` privileges, essential for querying internal `SYS` objects and performing administrative enumeration.
- **Smart Scoping**: Automatically uses the best available data dictionary views (`DBA_`, `ALL_`, `USER_`) based on the current user's permissions. This ensures that enumeration categories like `dblinks` and `sensitive` return the maximum possible data.
- **Context-Aware Sensitive Data Hunting**: When searching source code (`-k sensitive`), the tool automatically provides the 3 lines before and after a keyword match, giving you immediate context for analysis.
- **OPSEC-Aware Enumeration**: Before executing a potentially large number of enumeration queries, the script displays a count and prompts the user for confirmation, preventing accidental "noisy" scans.
- **Verbose Logging**: Includes an optional log file (`-L`) and verbose console output (`-v`) that shows every SQL query being executed for full transparency.
- **Multiple Output Formats**: Generate reports in `Excel`, `CSV`, or `JSON`.

## Requirements

- **Python 3.6+**
- The **`oracledb`** (formerly `cx_Oracle`), **`pandas`**, and **`openpyxl`** Python packages.
  ```bash
  pip install oracledb pandas openpyxl
  ```
- **Oracle Instant Client**: If using Thick mode, the Oracle Instant Client libraries must be installed and accessible on your system.

## Usage

The script detects the desired mode of operation based on the flags provided.

```
usage: ora_enum.py [-h] [-C list] [-c pair] [--creds-file CREDS_FILE] [-P] [--as-sysdba] [--users-file USERS_FILE] [--pass-file PASS_FILE] [--login-user LOGIN_USER] [--login-pass LOGIN_PASS] [-D list] [-d dsn] [--dsn-file DSN_FILE]
                   [-T list] [-t name] [-s {dba,all,user,auto}] [-k include] [--search-terms SEARCH_TERMS] [-g] [-o output] [-O outdir] [-q SQL] [-i] [--force] [-L LOG_FILE] [-v]

Advanced Oracle Enumerator & Sprayer for Red Teams.

optional arguments:
  -h, --help            show this help message and exit
  -L LOG_FILE, --log-file LOG_FILE
                        Save verbose output to a log file.
  -v, --verbose         Increase verbosity (-v for INFO, -vv for DEBUG)

Credential & Connection (for Enum/Query Modes):
  -C list               Comma-separated list: user[:pw][@dsn],...
  -c pair               Single credential: user[:pw]
  --creds-file CREDS_FILE
                        File with one credential per line (user[:pw][@dsn]).
  -P, --ask-pass        Prompt for passwords interactively.
  --as-sysdba           Connect with SYSDBA privilege. OPSEC WARNING: This is highly audited.

Password Spraying Mode:
  --users-file USERS_FILE
                        File with one username per line.
  --pass-file PASS_FILE
                        File with one password per line.
  --login-user LOGIN_USER
                        Single username for spraying.
  --login-pass LOGIN_PASS
                        Single password for spraying.

DSN Management (All Modes):
  -D list, --dsn-list list
                        Comma-separated DSN list (e.g., host/svc,host2/svc2)
  -d dsn, --dsn dsn     Single DSN (shortcut for -D)
  --dsn-file DSN_FILE   File with one DSN per line.

Enumeration Mode:
  -T list               Target users to enumerate (comma-separated)
  -t name               Single target user to enumerate
  -s {dba,all,user,auto}, --scope {dba,all,user,auto}
                        View prefix to use. Default: auto
  -k include, --include include
                        Categories: roles,sys,obj,col,quotas,profile,dblinks,sensitive,schemas
  --search-terms SEARCH_TERMS
                        Keywords for 'sensitive' search
  -g, --grant-catalog-role
                        Attempt to grant SELECT_CATALOG_ROLE (AUDITED!)
  -o output, --output output
                        Formats: excel,csv,json
  -O outdir, --outdir outdir
                        Directory for result files

Direct Query Mode:
  -q SQL, --query SQL   Execute a single query and print results.
  -i, --interactive     Enter an interactive SQL shell.
  --force               Allow non-SELECT queries with -q (DANGEROUS).
```

### Understanding Key Concepts

#### DSN (Data Source Name) Format
A DSN string tells the Oracle client how to connect. Common formats include:
- **Easy Connect**: `hostname:port/service_name` (e.g., `db.example.com:1521/ORCLPDB1`)
- **TNS Name**: A name defined in your `tnsnames.ora` file (e.g., `PRODDB`)

#### Why `SYS` Queries Fail Without `--as-sysdba`
It is a core security feature of Oracle that even with the correct password, a standard login as `SYS` grants almost no privileges. This prevents accidental damage from simple tools or scripts.

- **Standard vs. Privileged Login**: To perform administrative actions or view internal `SYS`-owned tables, you **must** establish a privileged connection using `AS SYSDBA`.
- **"No Rows Returned"**: When you perform a standard login as `SYS`, you are not blocked with a "permission denied" error. Instead, the data dictionary views you query will simply appear empty. The database filters their content based on your low-privilege session, resulting in "no rows".
- **Is `--as-sysdba` Required?**: **Yes.** To access internal `SYS` objects (like `SYS.EXU10LNKU`), you must use this flag. There is no alternative, non-audited method. Discovering `SYS` credentials means your next step is to attempt a privileged login.

---

### Examples

#### 1. Basic Privilege & Schema Enumeration
Enumerate privileges for `scott`, saving to Excel. The script will prompt for confirmation before running the queries.
```bash
python3 ora_enum.py -c scott:tiger -d db.example.com:1521/ORCL -k roles,sys,schemas -v
# [OPSEC] About to execute 4 SQL statement(s) for target 'SCOTT' on db.example.com:1521/ORCL.
#     > Do you want to proceed? (y/N): y
```

#### 2. Password Spraying with File-Based Lists
Spray a list of passwords against a list of users on databases defined in a file.
```bash
# users.txt contains 'scott', 'system', 'sys'
# passwords.txt contains 'tiger', 'manager', 'oracle'
# dsns.txt contains 'db1.example.com:1521/DEV' and 'db2.example.com:1521/PROD'
python3 ora_enum.py --users-file users.txt --pass-file passwords.txt --dsn-file dsns.txt
```

#### 3. Hunting for Sensitive Data (with Context)
Log in as `appuser` and search for keywords. The output for source code will automatically include surrounding lines for context.
```bash
python3 ora_enum.py -c appuser:password123 -d appdb:1521/APP \
  -k sensitive \
  --search-terms "ssn,dob,api_key,secret" \
  -o json -O results -v
```

#### 4. Enumerating Targets Using a Credentials File and a Single DSN
Use a file for credentials and apply one DSN to all of them. This is useful for testing multiple accounts against the same database.
```bash
# creds.txt contains one credential per line:
# app_user:P@s$w0rd!
# dba_user:AnotherP@ss
python3 ora_enum.py --creds-file creds.txt -d db1.example.com:1521/SVC1 -k all -o json
```

#### 5. Direct Query as a Standard User
Quickly get the database version from a target.
```bash
python3 ora_enum.py -c user:pass -d db1:1521/SVC1 -q "SELECT banner FROM v\$version"
```

#### 6. Direct Query as SYSDBA
To query internal `SYS`-owned objects, you must connect as `SYSDBA`.
```bash
python3 ora_enum.py -c sys:MySysPassword -d db1:1521/SVC1 -q "SELECT * FROM SYS.EXU10LNKU" --as-sysdba
```

#### 7. Interactive SQL Session
For manual, exploratory queries, start an interactive session.
```bash
python3 ora_enum.py -c appuser:password123 -d appdb:1521/APP -i
# [OPSEC] About to start an interactive session for appuser@appdb:1521/APP
#     > Do you want to proceed? (y/N): y
# ---[ Starting Interactive SQL Session for appuser@appdb:1521/APP (Mode: Normal) ]---
# Type multi-line queries ending with a ';'. Type 'exit' or 'quit' to end the session.
# Connected to: 19.0.0.0.0
# appuser@APP> SELECT COUNT(*) FROM user_tables;
#
#    COUNT(*)
# 0       108
#
# appuser@APP> exit
```

## OPSEC Considerations

-   **`--as-sysdba` is extremely powerful.** A `SYSDBA` connection bypasses all standard privilege checks and gives you full control over the database. **Both successful and failed `SYSDBA` login attempts are almost always logged and will generate alerts.** Use it surgically and only when you have `SYS` credentials.
-   **Password Spraying is NOISY**. It generates many failed login attempts which can trigger alerts and cause account lockouts. Use with caution.
-   **Enumeration can be NOISY**. The new confirmation prompt helps prevent accidental scans, but be aware that running many queries against data dictionary views can still be detected by monitoring solutions.
-   **Use Files for Credentials**. Using `-P/--ask-pass` or `--creds-file` is strongly recommended over putting passwords on the command line to avoid them being stored in shell history.
-   **Audited Actions**. Actions like `--grant-catalog-role` or using `--force` with `-q` to run DDL/DML statements are highly likely to be audited.

## License
This tool is provided for educational and authorized security testing purposes only. Use of this tool for illegal or unauthorized activities is strictly prohibited. The author is not responsible for any misuse or damage caused by this tool.
