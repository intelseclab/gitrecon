// Smart scanning techniques for efficient reconnaissance

const ColorUtils = require('../utils/colors');

class SmartScanner {
    constructor() {
        // Cache for API responses to avoid redundant calls
        this.cache = new Map();
        this.cacheExpiry = 5 * 60 * 1000; // 5 minutes

        // Email patterns for validation and classification
        this.emailPatterns = {
            // Common noreply patterns to filter out
            noreply: [
                /noreply@/i,
                /no-reply@/i,
                /donotreply@/i,
                /^.+@users\.noreply\.github\.com$/i,
                /^.+@users\.noreply\.gitlab\.com$/i,
                /notifications@github\.com/i
            ],
            // Disposable email domains
            disposable: [
                'tempmail.org', 'guerrillamail.com', 'mailinator.com', '10minutemail.com',
                'throwaway.email', 'temp-mail.org', 'fakeinbox.com', 'getnada.com',
                'maildrop.cc', 'dispostable.com', 'yopmail.com', 'trashmail.com',
                'sharklasers.com', 'guerrillamail.info', 'grr.la'
            ],
            // Sensitive data patterns in commits
            sensitivePatterns: [
                /api[_-]?key/i,
                /secret[_-]?key/i,
                /password/i,
                /private[_-]?key/i,
                /access[_-]?token/i,
                /auth[_-]?token/i,
                /bearer/i,
                /aws[_-]?secret/i,
                /credentials/i,
                /\.env/i,
                /config\.json/i,
                /id_rsa/i
            ]
        };

        // Priority scoring weights
        this.priorityWeights = {
            recentActivity: 30,      // Repos with recent commits
            hasDescription: 5,       // Repos with descriptions
            notFork: 20,             // Original repos (not forks)
            starCount: 10,           // Popular repos
            commitCount: 15,         // Active repos
            hasIssues: 5,            // Repos with issues enabled
            notArchived: 15          // Non-archived repos
        };
    }

    // Calculate priority score for a repository
    calculateRepoPriority(repo) {
        let score = 0;
        const now = new Date();

        // Recent activity (pushed in last 6 months gets full score)
        if (repo.pushed_at) {
            const pushedDate = new Date(repo.pushed_at);
            const monthsAgo = (now - pushedDate) / (1000 * 60 * 60 * 24 * 30);
            if (monthsAgo < 1) score += this.priorityWeights.recentActivity;
            else if (monthsAgo < 6) score += this.priorityWeights.recentActivity * 0.7;
            else if (monthsAgo < 12) score += this.priorityWeights.recentActivity * 0.3;
        }

        // Has description
        if (repo.description) score += this.priorityWeights.hasDescription;

        // Not a fork
        if (!repo.fork) score += this.priorityWeights.notFork;

        // Star count (logarithmic scaling)
        if (repo.stargazers_count > 0) {
            score += Math.min(Math.log10(repo.stargazers_count + 1) * 5, this.priorityWeights.starCount);
        }

        // Not archived
        if (!repo.archived) score += this.priorityWeights.notArchived;

        // Has issues enabled
        if (repo.has_issues) score += this.priorityWeights.hasIssues;

        return score;
    }

    // Sort repositories by priority for smarter scanning
    sortReposByPriority(repos) {
        return repos
            .map(repo => ({
                ...repo,
                priority: this.calculateRepoPriority(repo)
            }))
            .sort((a, b) => b.priority - a.priority);
    }

    // Filter repositories based on smart criteria
    filterRepos(repos, options = {}) {
        const {
            includeForks = false,
            includeArchived = false,
            minStars = 0,
            maxAge = null, // months
            maxRepos = null
        } = options;

        let filtered = repos.filter(repo => {
            // Fork filter
            if (!includeForks && repo.fork) return false;

            // Archived filter
            if (!includeArchived && repo.archived) return false;

            // Star filter
            if (repo.stargazers_count < minStars) return false;

            // Age filter
            if (maxAge && repo.pushed_at) {
                const pushedDate = new Date(repo.pushed_at);
                const monthsAgo = (new Date() - pushedDate) / (1000 * 60 * 60 * 24 * 30);
                if (monthsAgo > maxAge) return false;
            }

            return true;
        });

        // Sort by priority
        filtered = this.sortReposByPriority(filtered);

        // Limit if specified
        if (maxRepos && filtered.length > maxRepos) {
            filtered = filtered.slice(0, maxRepos);
        }

        return filtered;
    }

    // Validate and classify an email
    classifyEmail(email) {
        const result = {
            email,
            isValid: true,
            isNoreply: false,
            isDisposable: false,
            domain: null,
            classification: 'personal' // personal, work, noreply, disposable
        };

        // Extract domain
        const parts = email.split('@');
        if (parts.length !== 2) {
            result.isValid = false;
            return result;
        }
        result.domain = parts[1].toLowerCase();

        // Check noreply patterns
        for (const pattern of this.emailPatterns.noreply) {
            if (pattern.test(email)) {
                result.isNoreply = true;
                result.classification = 'noreply';
                return result;
            }
        }

        // Check disposable domains
        if (this.emailPatterns.disposable.includes(result.domain)) {
            result.isDisposable = true;
            result.classification = 'disposable';
            return result;
        }

        // Classify as work email if domain looks corporate
        const commonPersonalDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
                                        'live.com', 'icloud.com', 'protonmail.com', 'mail.com'];
        if (!commonPersonalDomains.includes(result.domain)) {
            result.classification = 'work';
        }

        return result;
    }

    // Deduplicate and enrich email results
    deduplicateEmails(emailsMap) {
        const enriched = new Map();

        for (const [email, names] of emailsMap.entries()) {
            const classification = this.classifyEmail(email);

            // Skip invalid or noreply emails by default
            if (!classification.isValid || classification.isNoreply) {
                continue;
            }

            enriched.set(email, {
                email,
                names: Array.from(names),
                classification: classification.classification,
                domain: classification.domain,
                isDisposable: classification.isDisposable
            });
        }

        return enriched;
    }

    // Analyze commit message for sensitive data patterns
    analyzeCommitMessage(message) {
        const findings = [];

        for (const pattern of this.emailPatterns.sensitivePatterns) {
            if (pattern.test(message)) {
                findings.push({
                    pattern: pattern.toString(),
                    match: message.match(pattern)?.[0]
                });
            }
        }

        return findings;
    }

    // Cache management
    getCached(key) {
        const cached = this.cache.get(key);
        if (!cached) return null;

        if (Date.now() > cached.expiry) {
            this.cache.delete(key);
            return null;
        }

        return cached.data;
    }

    setCache(key, data) {
        this.cache.set(key, {
            data,
            expiry: Date.now() + this.cacheExpiry
        });
    }

    clearCache() {
        this.cache.clear();
    }

    // Estimate API calls needed for a scan
    estimateApiCalls(repoCount, options = {}) {
        const {
            fetchProfile = true,
            fetchOrgs = true,
            fetchKeys = true,
            fetchGists = false,
            avgCommitsPerRepo = 50 // conservative estimate
        } = options;

        let calls = 0;

        if (fetchProfile) calls += 1;
        if (fetchOrgs) calls += 1;
        if (fetchKeys) calls += 1;
        if (fetchGists) calls += 1;

        // Repos list (paginated, assume 100 per page)
        calls += Math.ceil(repoCount / 100);

        // Commits for each repo (paginated)
        calls += repoCount * Math.ceil(avgCommitsPerRepo / 100);

        return calls;
    }

    // Generate scan strategy based on rate limits
    generateScanStrategy(repoCount, rateLimitRemaining, options = {}) {
        const estimatedCalls = this.estimateApiCalls(repoCount, options);

        const strategy = {
            canComplete: estimatedCalls <= rateLimitRemaining,
            estimatedCalls,
            rateLimitRemaining,
            recommendations: []
        };

        if (!strategy.canComplete) {
            // Calculate how many repos we can scan
            const callsPerRepo = this.estimateApiCalls(1, options);
            const safeRepoCount = Math.floor((rateLimitRemaining - 10) / callsPerRepo);

            strategy.recommendations.push({
                type: 'limit_repos',
                message: `Recommend limiting scan to ${safeRepoCount} repositories`,
                value: safeRepoCount
            });

            strategy.recommendations.push({
                type: 'use_token',
                message: 'Use a GitHub token to increase rate limit to 5000/hour'
            });

            strategy.recommendations.push({
                type: 'skip_forks',
                message: 'Skip forked repositories to reduce API calls'
            });
        }

        return strategy;
    }

    // Display smart scan summary
    displayScanSummary(repos, filteredRepos, options = {}) {
        console.log(ColorUtils.bright('\n=== SMART SCAN ANALYSIS ==='));
        console.log(`Total repositories: ${ColorUtils.cyan(repos.length)}`);
        console.log(`After filtering: ${ColorUtils.cyan(filteredRepos.length)}`);

        // Category breakdown
        const forks = repos.filter(r => r.fork).length;
        const archived = repos.filter(r => r.archived).length;
        const recent = repos.filter(r => {
            if (!r.pushed_at) return false;
            const monthsAgo = (new Date() - new Date(r.pushed_at)) / (1000 * 60 * 60 * 24 * 30);
            return monthsAgo < 6;
        }).length;

        console.log(`\nRepository breakdown:`);
        console.log(`  Original repos: ${ColorUtils.green(repos.length - forks)}`);
        console.log(`  Forked repos: ${ColorUtils.yellow(forks)}`);
        console.log(`  Archived repos: ${ColorUtils.dim(archived)}`);
        console.log(`  Active (6 months): ${ColorUtils.green(recent)}`);

        if (filteredRepos.length > 0) {
            console.log(`\nTop priority repositories:`);
            filteredRepos.slice(0, 5).forEach((repo, i) => {
                const repoData = repo.name ? repo : { name: repo, priority: 'N/A' };
                console.log(`  ${i + 1}. ${ColorUtils.cyan(repoData.name)} (priority: ${repoData.priority || 'N/A'})`);
            });
        }
    }
}

module.exports = SmartScanner;
