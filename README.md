# GitRecon - GitHub & GitLab OSINT Tool

A powerful reconnaissance tool to scan GitHub and GitLab profiles for exposed email addresses, SSH keys, and organizational data. Features smart scanning, deep analysis, and network mapping.

![screenshot](./demo.gif)

## Features

- **Email Discovery** - Extract emails from commit history, events, READMEs, and gists
- **Smart Scanning** - Prioritize active repos, filter noise, optimize API usage
- **Deep Analysis** - Scan gists, events, contributors, and documentation
- **Network Mapping** - Analyze followers/following and find mutual connections
- **Multi-Platform** - Support for both GitHub and GitLab
- **Multiple Outputs** - JSON, HTML reports with themes, or console output
- **Rate Limit Aware** - Intelligent request management with adaptive delays

## Installation

```bash
npm install -g gitrecon
```

Or clone and run locally:
```bash
git clone https://github.com/atiilla/gitrecon.git
cd gitrecon
npm install && npm link
gitrecon --help
```

## Quick Start

```bash
# Basic scan
gitrecon --user johndoe

# Smart scan (recommended)
gitrecon --user johndoe --smart

# Full reconnaissance
gitrecon --user johndoe --smart --deep --scan-network --output json
```

## Usage

### Target Options
```
-u, --user <username>      Scan a GitHub/GitLab user profile
-e, --email <email>        Find username by email and scan
-o, --org <organization>   Scan an organization/group
-r, --repository <repo>    Scan specific repository (requires --user)
```

### Smart Scanning Options (NEW)
```
--smart                    Enable smart mode: prioritizes active repos,
                           filters noreply emails, analyzes metadata
--deep                     Deep scan: gists, events, README, contributors
--max-age <months>         Only scan repos updated within N months
--parallel <number>        Parallel API requests (1-10, default: 3)
--skip-noreply             Skip noreply/automated email addresses
--scan-network             Map followers/following connections
--find-secrets             Detect potential secrets in commits
--export-network           Export network graph data
```

### Platform & Authentication
```
-s, --site <platform>      Platform: github (default) or gitlab
-t, --token <token>        API token for higher rate limits
-d, --delay <ms>           Delay between requests (default: 1000)
```

### Output Options
```
-p, --output <format>      Output format: json, html, or all
-v, --verbose              Show detailed output
--mask-emails              Mask emails for privacy in reports
--output-dir <path>        Custom output directory
--theme <theme>            HTML theme: default, dark, or security
```

### Other Options
```
-f, --include-forks        Include forked repositories
-a, --download-avatar      Download user avatar
--max-repos <number>       Limit repositories to scan
```

## Examples

### Basic Scanning
```bash
# Scan a GitHub user
gitrecon --user torvalds

# Scan a GitLab user
gitrecon --user johndoe --site gitlab

# Scan specific repository
gitrecon --user microsoft --repository vscode
```

### Smart Scanning (Recommended)
```bash
# Smart mode - filters noise, prioritizes active repos
gitrecon --user target --smart

# Smart + limit to repos updated in last 6 months
gitrecon --user target --smart --max-age 6

# Smart with verbose output
gitrecon --user target --smart --verbose
```

### Deep Reconnaissance
```bash
# Deep scan - includes gists, events, README emails
gitrecon --user target --deep

# Full recon - smart + deep + network
gitrecon --user target --smart --deep --scan-network

# Maximum intel with JSON export
gitrecon --user target --smart --deep --scan-network --output json
```

### Organization Scanning
```bash
# Scan organization
gitrecon --org microsoft

# GitLab group scan
gitrecon --org mygroup --site gitlab --verbose
```

### Email Lookup
```bash
# Find username by email and scan
gitrecon --email user@company.com
```

### Performance Optimization
```bash
# Use API token for 5000 req/hour (vs 60 unauthenticated)
gitrecon --user target --token ghp_xxxxxxxxxxxx

# Parallel requests for faster scanning
gitrecon --user target --parallel 5 --token ghp_xxx

# Limit scope for quick scan
gitrecon --user target --max-repos 10 --max-age 3
```

### Output Formats
```bash
# Save as HTML report
gitrecon --user target --output html

# Save as JSON data
gitrecon --user target --output json

# Both formats with dark theme
gitrecon --user target --output all --theme dark

# Custom output directory
gitrecon --user target --output html --output-dir ./reports
```

## Smart Scanning Features

### Priority-Based Repository Analysis
Smart mode scores repositories based on:
- **Recent activity** - Repos pushed to recently get priority
- **Original content** - Non-forked repos prioritized
- **Popularity** - Star count considered
- **Active status** - Non-archived repos preferred

### Email Classification
Emails are automatically classified as:
- `personal` - Gmail, Yahoo, etc.
- `work` - Corporate domains
- `noreply` - Automated/GitHub noreply (filtered in smart mode)
- `disposable` - Temporary email services

### Deep Scan Sources
With `--deep` flag, the tool scans:
1. **Commit history** - Author/committer emails
2. **Public events** - Push event payloads
3. **Gists** - User's code snippets
4. **README files** - Contact information
5. **Contributors** - Anonymous contributor emails

## Rate Limits

| Platform | Unauthenticated | With Token |
|----------|-----------------|------------|
| GitHub   | 60/hour         | 5,000/hour |
| GitLab   | 300/minute      | 2,000/minute |

**Tip:** Always use a token for serious scanning:
- GitHub: https://github.com/settings/tokens
- GitLab: https://gitlab.com/-/profile/personal_access_tokens

## Output Examples

### Console Output
```
= RECONNAISSANCE COMPLETED =
User: johndoe (John Doe)
URL: https://github.com/johndoe
Organizations: acme-corp, open-source-org
Public Keys: 2
Leaked Emails: 5

Leaked Emails:
| email                  | names      | type     | sources |
|------------------------|------------|----------|---------|
| john@company.com       | John Doe   | work     | 3       |
| johnd@gmail.com        | John D     | personal | 2       |
```

### JSON Output
```json
{
  "username": "johndoe",
  "name": "John Doe",
  "email_details": [
    {
      "email": "john@company.com",
      "names": ["John Doe"],
      "classification": "work",
      "domain": "company.com",
      "sources": ["commit", "readme"],
      "repositories": ["project1", "project2"]
    }
  ],
  "network": {
    "followers_count": 150,
    "following_count": 45,
    "mutual_follows": ["colleague1", "colleague2"]
  }
}
```

## Ethics & Disclaimer

This tool is intended for **educational and ethical security research purposes only**.

By using this tool, you agree to:
1. Only scan profiles you own or have explicit permission to analyze
2. Respect GitHub/GitLab Terms of Service and API rate limits
3. Use collected information responsibly and in compliance with applicable laws
4. Not use this tool for harassment, stalking, or privacy violations

**The authors disclaim all liability for misuse of this tool.**

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

[Atilla](https://github.com/atiilla)
