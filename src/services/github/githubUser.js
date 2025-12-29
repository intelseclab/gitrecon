// GitHub user reconnaissance - Enhanced with smart scanning

const GitHubApi = require('./githubApi');
const FileUtils = require('../../utils/fileUtils');
const ColorUtils = require('../../utils/colors');
const SmartScanner = require('../../core/smartScanner');

// Merge two email maps
const mergeEmailMaps = (target, source) => {
    for (const [email, names] of source.entries()) {
        if (!target.has(email)) {
            target.set(email, new Set());
        }
        names.forEach(name => target.get(email).add(name));
    }
    return target;
};

// Function to run GitHub reconnaissance - Enhanced version
const runGithubRecon = async (username, options = {}) => {
    const {
        downloadAvatarFlag = false,
        saveFork = false,
        outputFormat = null,
        verbose = false,
        smart = false,
        deep = false,
        maxAge = null,
        parallel = 3,
        skipNoreply = false,
        scanNetwork = false,
        findSecrets = false,
        exportNetwork = false,
        maxRepos = null
    } = options;

    const smartScanner = new SmartScanner();

    console.info(ColorUtils.green(`Running GitHub reconnaissance on user "${ColorUtils.yellow(username)}"`));

    if (smart) {
        console.info(ColorUtils.cyan('Smart scanning mode enabled'));
    }
    if (deep) {
        console.info(ColorUtils.cyan('Deep scanning mode enabled'));
    }

    // Create output directory if it doesn't exist
    const outputDir = FileUtils.createOutputDirectory();

    // Prepare result object with basic structure
    let result = {
        username: username,
        scan_started_at: new Date().toISOString(),
        scan_mode: { smart, deep, parallel },
        organizations: [],
        leaked_emails: [],
        email_details: [],
        keys: [],
        gists: [],
        events_summary: {},
        network: {},
        secrets_found: []
    };

    // Check rate limit before starting
    try {
        const rateLimitData = await GitHubApi.getRateLimit();
        if (rateLimitData && rateLimitData.resources && rateLimitData.resources.core) {
            const remaining = rateLimitData.resources.core.remaining;
            const limit = rateLimitData.resources.core.limit;
            console.log(ColorUtils.dim(`Rate limit: ${remaining}/${limit}`));

            if (remaining < 50) {
                console.warn(ColorUtils.yellow(`Warning: You have only ${remaining} GitHub API requests remaining.`));
                console.warn(ColorUtils.yellow('Consider using a GitHub token with --token option.'));
            }

            // If smart mode, generate strategy
            if (smart) {
                const strategy = smartScanner.generateScanStrategy(100, remaining, { fetchGists: deep });
                if (!strategy.canComplete) {
                    console.warn(ColorUtils.yellow('\nSmart Scanner Recommendations:'));
                    strategy.recommendations.forEach(rec => {
                        console.warn(ColorUtils.yellow(`  - ${rec.message}`));
                    });
                }
            }
        }
    } catch (error) {
        // Continue anyway if rate limit check fails
    }

    // Fetch profile info
    const userInfo = await GitHubApi.getUserProfile(username);
    if (!userInfo || userInfo.error || (userInfo.message && userInfo.message.includes('Not Found'))) {
        console.error(ColorUtils.red(`Error: GitHub user "${username}" not found`));
        return null;
    }

    // Update result with user info
    Object.assign(result, {
        username: userInfo.login,
        name: userInfo.name,
        id: userInfo.id,
        avatar_url: userInfo.avatar_url,
        email: userInfo.email,
        location: userInfo.location,
        bio: userInfo.bio,
        company: userInfo.company,
        blog: userInfo.blog,
        twitter_username: userInfo.twitter_username,
        followers: userInfo.followers,
        following: userInfo.following,
        public_repos: userInfo.public_repos,
        public_gists: userInfo.public_gists,
        created_at: userInfo.created_at,
        updated_at: userInfo.updated_at,
        hireable: userInfo.hireable
    });

    // If profile has public email, add it
    if (userInfo.email) {
        result.profile_email = userInfo.email;
    }

    // Save initial data
    FileUtils.saveRealTime(result, username, 'github', outputDir);

    console.log(ColorUtils.green(`Found GitHub user: ${ColorUtils.yellow(userInfo.login || username)} (${ColorUtils.yellow(userInfo.name || 'No name')})`));
    console.log(ColorUtils.dim(`  Created: ${userInfo.created_at} | Repos: ${userInfo.public_repos} | Gists: ${userInfo.public_gists}`));

    // Fetch organizations
    const orgsData = await GitHubApi.getUserOrganizations(username);
    let orgs = [];

    if (Array.isArray(orgsData)) {
        orgs = orgsData.map(org => ({
            login: org.login,
            id: org.id,
            description: org.description,
            avatar_url: org.avatar_url
        }));
        if (orgs.length > 0) {
            console.log(ColorUtils.green(`Found ${ColorUtils.yellow(orgs.length)} organizations: ${ColorUtils.yellow(orgs.map(o => o.login).join(', '))}`));
        } else {
            console.log(ColorUtils.green('No organizations found'));
        }

        result.organizations = orgs;
        FileUtils.saveRealTime(result, username, 'github', outputDir);
    }

    // Fetch public SSH keys
    const keysData = await GitHubApi.getUserKeys(username);
    let keys = [];

    if (Array.isArray(keysData)) {
        keys = keysData;
        if (keys.length > 0) {
            console.log(ColorUtils.green(`Found ${ColorUtils.yellow(keys.length)} public SSH keys`));
        } else {
            console.log(ColorUtils.green('No public SSH keys found'));
        }

        result.keys = keys.map(key => ({
            id: key.id,
            key: key.key
        }));
        FileUtils.saveRealTime(result, username, 'github', outputDir);
    }

    // Initialize email tracking
    const emailsToName = new Map();
    const emailsToRepo = new Map();
    const emailSources = new Map(); // Track where each email was found

    // Get repositories with full metadata for smart scanning
    let repositories;
    if (smart) {
        console.log(ColorUtils.cyan('Fetching repository metadata for smart analysis...'));
        repositories = await GitHubApi.getRepositoriesDetailed(username);
    } else {
        repositories = await GitHubApi.getRepositories(username);
    }

    console.log(ColorUtils.green(`Found ${ColorUtils.yellow(repositories.length)} public repositories`));

    // Apply smart filtering if enabled
    let reposToScan;
    if (smart) {
        reposToScan = smartScanner.filterRepos(repositories, {
            includeForks: saveFork,
            includeArchived: false,
            maxAge: maxAge,
            maxRepos: maxRepos
        });

        // Display smart scan summary
        smartScanner.displayScanSummary(repositories, reposToScan);
    } else {
        // Traditional filtering
        reposToScan = repositories
            .filter(repo => !repo.fork || saveFork)
            .slice(0, maxRepos || repositories.length);
    }

    const repoNames = reposToScan.map(repo => repo.name || repo);
    console.log(ColorUtils.green(`Scanning ${ColorUtils.yellow(repoNames.length)} repositories for leaked emails`));

    // Scan each repository for commits
    const totalRepos = repoNames.length;
    for (let i = 0; i < totalRepos; i++) {
        const repo = repoNames[i];
        process.stdout.write(ColorUtils.green(`Scanning repository ${ColorUtils.yellow(`${i + 1}/${totalRepos}`)}: ${ColorUtils.cyan(repo)}...`));

        try {
            const newEmails = await GitHubApi.getEmails(username, repo);
            process.stdout.write('\r' + ' '.repeat(100) + '\r');

            let newEmailsCount = 0;

            for (const [email, names] of newEmails.entries()) {
                // Smart filtering: skip noreply if enabled
                if (skipNoreply || smart) {
                    const classification = smartScanner.classifyEmail(email);
                    if (classification.isNoreply) {
                        if (verbose) {
                            console.log(ColorUtils.dim(`  Skipping noreply: ${email}`));
                        }
                        continue;
                    }
                }

                if (!emailsToRepo.has(email)) {
                    emailsToRepo.set(email, new Set());
                }
                emailsToRepo.get(email).add(repo);

                if (!emailSources.has(email)) {
                    emailSources.set(email, new Set());
                }
                emailSources.get(email).add('commit');

                if (!emailsToName.has(email)) {
                    emailsToName.set(email, new Set());
                    newEmailsCount++;
                }

                names.forEach(name => emailsToName.get(email).add(name));
            }

            if (newEmailsCount > 0) {
                console.log(ColorUtils.green(`Found ${ColorUtils.yellow(newEmailsCount)} new emails in ${ColorUtils.cyan(repo)}`));

                // Update result
                updateResultEmails(result, emailsToName, emailsToRepo, emailSources, smartScanner, skipNoreply || smart);
                result.scan_progress = `${i + 1}/${totalRepos} repositories scanned`;
                FileUtils.saveRealTime(result, username, 'github', outputDir);
            }
        } catch (error) {
            process.stdout.write('\r' + ' '.repeat(100) + '\r');
            if (verbose) {
                console.error(ColorUtils.red(`Error scanning ${repo}: ${error.message}`));
            }
        }
    }

    // Deep scanning: Gists
    if (deep) {
        console.log(ColorUtils.cyan('\nDeep scan: Checking gists...'));
        try {
            const gists = await GitHubApi.getUserGists(username);
            result.gists = gists.map(g => ({
                id: g.id,
                description: g.description,
                public: g.public,
                created_at: g.created_at,
                updated_at: g.updated_at,
                files: Object.keys(g.files)
            }));
            console.log(ColorUtils.green(`Found ${ColorUtils.yellow(gists.length)} gists`));
        } catch (error) {
            if (verbose) console.error(ColorUtils.dim(`Error fetching gists: ${error.message}`));
        }
    }

    // Deep scanning: Events (contains emails from push events)
    if (deep) {
        console.log(ColorUtils.cyan('Deep scan: Checking public events...'));
        try {
            const events = await GitHubApi.getUserEvents(username, { maxPages: 3 });
            const eventEmails = GitHubApi.extractEmailsFromEvents(events);

            let newFromEvents = 0;
            for (const [email, names] of eventEmails.entries()) {
                if (skipNoreply || smart) {
                    const classification = smartScanner.classifyEmail(email);
                    if (classification.isNoreply) continue;
                }

                if (!emailsToName.has(email)) {
                    emailsToName.set(email, new Set());
                    newFromEvents++;
                }
                names.forEach(name => emailsToName.get(email).add(name));

                if (!emailSources.has(email)) {
                    emailSources.set(email, new Set());
                }
                emailSources.get(email).add('event');
            }

            // Summarize events
            const eventTypes = {};
            events.forEach(e => {
                eventTypes[e.type] = (eventTypes[e.type] || 0) + 1;
            });
            result.events_summary = eventTypes;

            if (newFromEvents > 0) {
                console.log(ColorUtils.green(`Found ${ColorUtils.yellow(newFromEvents)} new emails from events`));
            }
            console.log(ColorUtils.dim(`  Event types: ${Object.entries(eventTypes).map(([k, v]) => `${k}:${v}`).join(', ')}`));
        } catch (error) {
            if (verbose) console.error(ColorUtils.dim(`Error fetching events: ${error.message}`));
        }
    }

    // Deep scanning: README emails
    if (deep && repoNames.length > 0) {
        console.log(ColorUtils.cyan('Deep scan: Checking READMEs for contact info...'));
        const readmeEmails = new Set();

        // Check top 5 repos
        for (const repo of repoNames.slice(0, 5)) {
            try {
                const readme = await GitHubApi.getRepoReadme(username, repo);
                if (readme) {
                    const extracted = GitHubApi.extractEmailsFromText(readme);
                    extracted.forEach(email => {
                        if (skipNoreply || smart) {
                            const classification = smartScanner.classifyEmail(email);
                            if (classification.isNoreply) return;
                        }
                        readmeEmails.add(email);

                        if (!emailsToName.has(email)) {
                            emailsToName.set(email, new Set());
                        }
                        emailsToName.get(email).add('README');

                        if (!emailSources.has(email)) {
                            emailSources.set(email, new Set());
                        }
                        emailSources.get(email).add('readme');
                    });
                }
            } catch (error) {
                // Silently skip
            }
        }

        if (readmeEmails.size > 0) {
            console.log(ColorUtils.green(`Found ${ColorUtils.yellow(readmeEmails.size)} emails in READMEs`));
        }
    }

    // Network scanning
    if (scanNetwork || exportNetwork) {
        console.log(ColorUtils.cyan('\nScanning network connections...'));
        try {
            const network = await GitHubApi.getUserNetwork(username, {
                maxFollowers: 100,
                maxFollowing: 100
            });

            result.network = {
                followers_count: network.followers.length,
                following_count: network.following.length,
                followers: network.followers.map(f => ({
                    login: f.login,
                    id: f.id,
                    avatar_url: f.avatar_url
                })),
                following: network.following.map(f => ({
                    login: f.login,
                    id: f.id,
                    avatar_url: f.avatar_url
                }))
            };

            console.log(ColorUtils.green(`Network: ${ColorUtils.yellow(network.followers.length)} followers, ${ColorUtils.yellow(network.following.length)} following`));

            // Find potential team members (mutual follows)
            const followerLogins = new Set(network.followers.map(f => f.login));
            const mutualFollows = network.following.filter(f => followerLogins.has(f.login));
            if (mutualFollows.length > 0) {
                result.network.mutual_follows = mutualFollows.map(f => f.login);
                console.log(ColorUtils.dim(`  Mutual connections: ${mutualFollows.length}`));
            }
        } catch (error) {
            if (verbose) console.error(ColorUtils.dim(`Error fetching network: ${error.message}`));
        }
    }

    // Secret finding in commit messages
    if (findSecrets) {
        console.log(ColorUtils.cyan('\nScanning for potential secrets in commit messages...'));
        result.secrets_found = [];

        // This would require fetching commit messages, which is expensive
        // For now, we'll note that this feature is available
        console.log(ColorUtils.dim('  Note: Secret scanning requires additional API calls'));
        console.log(ColorUtils.dim('  Use with specific repos: --user <user> --repository <repo> --find-secrets'));
    }

    // Update final email results
    updateResultEmails(result, emailsToName, emailsToRepo, emailSources, smartScanner, skipNoreply || smart);

    // Display results
    console.log(`\n${ColorUtils.green('=')} ${ColorUtils.bright('RECONNAISSANCE COMPLETED')} ${ColorUtils.green('=')}`);
    console.log(ColorUtils.green(`User: ${ColorUtils.yellow(`${userInfo.login} (${userInfo.name || 'No name'})`)}`));
    console.log(ColorUtils.green(`URL: ${ColorUtils.cyan(`https://github.com/${username}`)}`));
    console.log(ColorUtils.green(`Organizations: ${ColorUtils.yellow(orgs.length > 0 ? orgs.map(o => o.login).join(', ') : 'None')}`));
    console.log(ColorUtils.green(`Public Keys: ${ColorUtils.yellow(keys.length)}`));
    console.log(ColorUtils.green(`Leaked Emails: ${ColorUtils.yellow(result.leaked_emails.length)}`));

    if (keys.length > 0) {
        console.log(`\n${ColorUtils.yellow('Public SSH Keys:')}`);
        keys.forEach((key, index) => {
            console.log(ColorUtils.cyan(`Key #${index + 1}:`));
            console.log(`${key.key.substring(0, 50)}...`);
        });
    }

    if (result.leaked_emails.length > 0) {
        console.log(`\n${ColorUtils.yellow('Leaked Emails:')}`);

        const emailTable = result.email_details.map(detail => ({
            email: detail.email,
            names: detail.names.join(', ').substring(0, 25) + (detail.names.join(', ').length > 25 ? '...' : ''),
            type: detail.classification || 'unknown',
            sources: detail.sources ? detail.sources.length : 0
        }));

        console.table(emailTable);
    }

    // Finalize result
    result.scan_completed_at = new Date().toISOString();
    result.scan_progress = 'completed';
    result.scan_stats = {
        repos_scanned: repoNames.length,
        total_repos: repositories.length,
        emails_found: result.leaked_emails.length,
        keys_found: keys.length,
        orgs_found: orgs.length
    };

    // Download avatar if requested
    if (downloadAvatarFlag && userInfo.avatar_url) {
        await FileUtils.downloadAvatar(userInfo.avatar_url, username, 'github');
    }

    // Save final output if requested
    if (outputFormat) {
        FileUtils.saveOutput(result, outputFormat, username, 'github');
    }

    return result;
};

// Helper function to update result emails
function updateResultEmails(result, emailsToName, emailsToRepo, emailSources, smartScanner, filterNoreply) {
    const allEmails = [];
    const emailDetails = [];

    for (const [email, namesSet] of emailsToName.entries()) {
        const classification = smartScanner.classifyEmail(email);

        if (filterNoreply && classification.isNoreply) {
            continue;
        }

        allEmails.push(email);
        emailDetails.push({
            email,
            names: Array.from(namesSet),
            classification: classification.classification,
            domain: classification.domain,
            is_disposable: classification.isDisposable,
            sources: Array.from(emailSources.get(email) || []),
            repositories: Array.from(emailsToRepo.get(email) || [])
        });
    }

    result.leaked_emails = allEmails;
    result.email_details = emailDetails;
}

class GitHubUser {
    static runRecon = runGithubRecon;
}

module.exports = GitHubUser;
