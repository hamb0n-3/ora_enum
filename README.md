Of course. A well-documented tool is an effective tool. I have updated the `README.md` to reflect all the recent fixes and enhancements, including the more robust credential parsing and the new `--creds-file` argument for easier scripting.

Here is the updated `README.md`:

---

# `ora_enum`: Advanced Oracle Enumerator & Sprayer for Red Teams

`ora_enum` is a powerful, multi-modal Python script designed for penetration testers and red teamers to rapidly enumerate privileges, discover sensitive data, spray credentials, and execute direct queries within Oracle databases.

This tool helps answer critical questions during an assessment:
- **(Spray)** Which default or weak credentials are valid?
- **(Enumerate)** What can this user see and do? Are there clear paths to escalate privileges?
- **(Hunt)** Where is the sensitive data (PII, credentials, keys)?
- **(Query)** Can I surgically extract specific information?

## Features

- **Multiple Modes of Operation**:
  - **Enumeration Mode**: Deeply audits a user's permissions and finds sensitive data.
  - **Password Spraying Mode**: Efficiently tests lists of usernames and passwords against multiple databases.
  - **Direct Query Mode**: Executes a single SQL query for targeted data gathering.
- **Flexible Credential Handling**: Provide credentials individually (`-c`), as a comma-separated list (`-C`), from a file (`--creds-file`), or use an interactive prompt (`-P`). The parsing logic is robust against special characters in passwords.
- **Smart Scoping**: Automatically uses the best available data dictionary views (`DBA_`, `ALL_`, `USER_`) based on the current user's permissions.
- **Actionable Privilege Analysis**: Automatically identifies and flags high-impact privileges that can lead to privilege escalation.
- **Configurable Sensitive Data Hunting**:
  - A dedicated `sensitive` category to find PII, credentials, API keys, etc.
  - Searches for keywords in both table/column names and PL/SQL source code.
- **Multiple Output Formats**: Generate reports in `Excel`, `CSV`, or `JSON`.

## Requirements

- **Python 3.6+**
- The **`oracledb`**, **`pandas`**, and **`openpyxl`** Python packages.
  ```bash
  pip install oracledb pandas openpyxl
  ```
- **Oracle Instant Client**: If using the Thick mode of `oracledb`, the Oracle Instant Client libraries must be installed and accessible.

## Usage

The script detects the desired mode of operation based on the flags provided.

```
usage: ora_enum.py [-h] [-C list] [-c pair] [--creds-file CREDS_FILE] [-P] [--users-file USERS_FILE] [--pass-file PASS_FILE] [--login-user LOGIN_USER] [--login-pass LOGIN_PASS] [-D list] [-d dsn] [-T list]
                   [-t name] [-s {dba,all,user,auto}] [-k include] [--search-terms SEARCH_TERMS] [-g] [-o output] [-O outdir] [-q SQL] [--force] [-v]

Advanced Oracle Enumerator & Sprayer for Red Teams.

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Increase verbosity (-v for INFO, -vv for DEBUG)

Credential & Connection (for Enum/Query Modes):
  -C list               Comma-separated list: user[:pw][@dsn],...
  -c pair               Single credential: user[:pw]
  --creds-file CREDS_FILE
                        File with one credential per line (user[:pw][@dsn]).
  -P, --ask-pass        Prompt for passwords interactively.

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

Enumeration Mode:
  -T list, --target-list list
                        Target users to enumerate (comma-separated)
  -t name, --target-user name
                        Single target user to enumerate
  -s {dba,all,user,auto}, --scope {dba,all,user,auto}
                        View prefix to use. Default: auto
  -k include, --include include
                        Categories: roles,sys,obj,col,quotas,profile,dblinks,sensitive
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
  --force               Allow non-SELECT queries with -q (DANGEROUS).
```

### DSN (Data Source Name) Format
A DSN string tells the Oracle client how to connect. Common formats include:
- **Easy Connect**: `hostname:port/service_name` (e.g., `db.example.com:1521/ORCLPDB1`)
- **TNS Name**: A name defined in your `tnsnames.ora` file (e.g., `PRODDB`)

---

### Examples

#### 1. Basic Privilege Enumeration
Enumerate the privileges of the logged-in user (`scott`) and save to Excel.

```bash
python3 ora_enum.py -c scott:tiger -d db.example.com:1521/ORCL
```

#### 2. Password Spraying with a List
Spray a list of common passwords against a list of users on two databases.

```bash
# users.txt contains 'scott', 'system', 'sys'
# passwords.txt contains 'tiger', 'manager', 'oracle'
python3 ora_enum.py --users-file users.txt --pass-file passwords.txt -D "db1:1521/DEV,db2:1521/PROD"
```
*Output will highlight any successful logins with `[+] SUCCESS`.*

#### 3. Spraying a Single Password (Seasonal Password Attack)
Test if any user from a list has a common seasonal password.

```bash
python3 ora_enum.py --users-file users.txt --login-pass "Winter2024!" -D db.example.com:1521/ORCL
```

#### 4. Brute-Forcing a Single Account
Try a list of passwords against the `system` account.

```bash
python3 ora_enum.py --login-user system --pass-file common-passwords.txt -D db.example.com:1521/ORCL -vv
```
*Using `-vv` will show every failed attempt for debugging.*

#### 5. Hunting for Sensitive Data
Log in and hunt for any columns or source code containing PII or credentials.

```bash
python3 ora_enum.py -c appuser:password123 -d appdb:1521/APP \
  -k sensitive \
  --search-terms "ssn,dob,api_key,secret"
```

#### 6. Enumerating Targets Using a Credentials File
Use a file to provide credentials, which is ideal for handling passwords with special characters that might conflict with shell parsing.

```bash
# creds.txt contains one credential per line:
# app_user:P@s$w0rd!/With$pecial@appdb:1521/SVC1
# dba_user:AnotherP@ss@db2:1521/SVC2
python3 ora_enum.py --creds-file creds.txt -k sensitive -o json
```

#### 7. Direct Query Mode
Quickly get the database version from a target.

```bash
python3 ora_enum.py -c user:pass -d db1:1521/SVC1 -q "SELECT banner FROM v\$version"
```

## OPSEC Considerations

- **Password Spraying is NOISY**. It generates many failed login attempts which can trigger alerts and cause account lockouts. Use with caution.
- Using `-P/--ask-pass` is recommended over putting passwords on the command line to avoid them being stored in shell history.
- Using the `--creds-file` flag is the most reliable way to handle credentials with special characters.
- Actions like `--grant-catalog-role` or using `--force` with `-q` are DDL/DML operations and are highly likely to be audited.

## License
This tool is provided for educational and authorized security testing purposes only. Use of this tool for illegal or unauthorized activities is strictly prohibited. The author is not responsible for any misuse or damage caused by this tool.
