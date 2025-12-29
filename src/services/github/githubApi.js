// GitHub API specific functions

const ApiUtils = require('../../utils/apiUtils');
const ColorUtils = require('../../utils/colors');
const { API_URL, getDelay } = require('../../config/constants');
const { Repository } = require('../../config/settings');

// Parallel request helper with concurrency control
const parallelRequests = async (urls, options = {}) => {
    const { concurrency = 3, onProgress = null } = options;
    const results = [];
    let completed = 0;

    for (let i = 0; i < urls.length; i += concurrency) {
        const batch = urls.slice(i, i + concurrency);
        const batchResults = await Promise.all(
            batch.map(url => ApiUtils.call(url))
        );
        results.push(...batchResults);
        completed += batch.length;

        if (onProgress) {
            onProgress(completed, urls.length);
        }
    }

    return results;
};

// Function to retrieve user's repositories - orijinal koddan
const getRepositories = async (username) => {
    const repositoriesSeen = new Set();
    const repositories = [];
    let pageCounter = 1;

    while (true) {
        let continueLoop = true;

        // Construct the URL for fetching repositories
        const url = `${API_URL}/users/${username}/repos?per_page=100&page=${pageCounter}`;
        const result = await ApiUtils.call(url);        if ('message' in result || result.error || !Array.isArray(result)) {
            if (result.message && result.message.includes('API rate limit exceeded for ')) {
                console.warn('API rate limit exceeded - not all repos were fetched');
                break;
            }
            if (result.message === 'Not Found') {
                console.warn(`There is no user with the username "${username}"`);
                break;
            }
            // If there's any other error, break the loop
            console.warn(ColorUtils.yellow(`Error fetching repositories: ${result.message || 'Unknown error'}`));
            break;
        }

        // Process each repository in the result
        if (Array.isArray(result)) {
            for (const repository of result) {
                const repoName = repository.name;
                if (repositoriesSeen.has(repoName)) {
                    continueLoop = false;
                    break;
                } else {
                    repositories.push(Repository(repoName, repository.fork));
                    repositoriesSeen.add(repoName);
                }
            }
        } else {
            // If result is not an array, we can't process it
            break;
        }

        if (continueLoop && Array.isArray(result) && result.length === 100) {
            pageCounter += 1;
        } else {
            break;
        }
    }

    return repositories;
};

// Function to retrieve email addresses from a repository's commits
const getEmails = async (username, repoName) => {
    const emailsToName = new Map();
    const seenCommits = new Set();
    let pageCounter = 1;
    let commitCounter = 1;

    while (true) {
        let continueLoop = true;
        const url = `${API_URL}/repos/${username}/${repoName}/commits?per_page=100&page=${pageCounter}`;
        const result = await ApiUtils.call(url);        if ('message' in result || result.error || !Array.isArray(result)) {
            if (result.message === 'Git Repository is empty.' || result.message === 'No commit found') {
                console.info(ColorUtils.yellow(`Repository ${repoName} is empty - skipping`));
                return emailsToName;
            }

            if (result.message && result.message.includes('API rate limit exceeded for ')) {
                console.warn('API rate limit exceeded');
                return emailsToName;
            }

            if (result.message === 'Not Found') {
                console.warn(`Repository Not Found: "${repoName}"`);
                return emailsToName;
            }

            // If there's any other error, return what we have
            console.warn(ColorUtils.yellow(`Error fetching commits for ${repoName}: ${result.message || 'Unknown error'}`));
            return emailsToName;
        }

        // Process each commit in the result
        if (Array.isArray(result)) {
            for (const commit of result) {
                const sha = commit.sha;
                if (seenCommits.has(sha)) {
                    continueLoop = false;
                    break;
                }

                seenCommits.add(sha);
                // console.info(`Scanning commit -> ${commitCounter}`);
                commitCounter += 1;

                if (!commit.author) {
                    continue;
                }
                const user = commit.author.login;
                if (user.toLowerCase() === username.toLowerCase()) {
                    const { author, committer } = commit.commit;
                    const authorName = author.name;
                    const authorEmail = author.email;
                    const committerName = committer.name;
                    const committerEmail = committer.email;
                    if (authorEmail) {
                        if (!emailsToName.has(authorEmail)) {
                            emailsToName.set(authorEmail, new Set());
                        }
                        emailsToName.get(authorEmail).add(authorName);
                    }
                    if (committerEmail) {
                        if (!emailsToName.has(committerEmail)) {
                            emailsToName.set(committerEmail, new Set());
                        }
                        emailsToName.get(committerEmail).add(committerName);
                    }
                }
            }
        } else {
            // If result is not an array, we can't process it
            break;
        }

        if (continueLoop && Array.isArray(result) && result.length === 100) {
            pageCounter += 1;
        } else {
            break;
        }
    }

    return emailsToName;
};

class GitHubApi {
    static getRepositories = getRepositories;
    static getEmails = getEmails;
    static parallelRequests = parallelRequests;

    // User profile methods
    static async getUserProfile(username) {
        return await ApiUtils.call(`${API_URL}/users/${username}`);
    }

    static async getUserOrganizations(username) {
        return await ApiUtils.call(`${API_URL}/users/${username}/orgs`);
    }

    static async getUserKeys(username) {
        return await ApiUtils.call(`${API_URL}/users/${username}/keys`);
    }

    static async getRateLimit() {
        return await ApiUtils.call(`${API_URL}/rate_limit`);
    }

    // Gist methods for additional email discovery
    static async getUserGists(username) {
        const gists = [];
        let page = 1;

        while (true) {
            const url = `${API_URL}/users/${username}/gists?per_page=100&page=${page}`;
            const result = await ApiUtils.call(url);

            if (!Array.isArray(result) || result.length === 0) break;

            gists.push(...result);
            if (result.length < 100) break;
            page++;
        }

        return gists;
    }

    // Get emails from gist commits
    static async getGistEmails(gistId) {
        const emailsToName = new Map();
        const url = `${API_URL}/gists/${gistId}/commits`;
        const result = await ApiUtils.call(url);

        if (!Array.isArray(result)) return emailsToName;

        for (const commit of result) {
            if (commit.user && commit.change_status) {
                const user = commit.user;
                // Gist commits don't expose email directly, but we can get user info
                if (user.email) {
                    if (!emailsToName.has(user.email)) {
                        emailsToName.set(user.email, new Set());
                    }
                    emailsToName.get(user.email).add(user.login || user.name || 'Unknown');
                }
            }
        }

        return emailsToName;
    }

    // Get repository contributors with their emails
    static async getRepoContributors(owner, repo, options = {}) {
        const { includeAnonymous = true } = options;
        const contributors = [];
        let page = 1;

        while (true) {
            const url = `${API_URL}/repos/${owner}/${repo}/contributors?per_page=100&page=${page}&anon=${includeAnonymous ? '1' : '0'}`;
            const result = await ApiUtils.call(url);

            if (!Array.isArray(result) || result.length === 0) break;

            contributors.push(...result);
            if (result.length < 100) break;
            page++;
        }

        return contributors;
    }

    // Get all emails from all contributors in a repo
    static async getContributorEmails(owner, repo) {
        const emailsToName = new Map();

        // Get contributors including anonymous
        const contributors = await this.getRepoContributors(owner, repo, { includeAnonymous: true });

        for (const contributor of contributors) {
            // Anonymous contributors have email and name directly
            if (contributor.type === 'Anonymous' && contributor.email) {
                if (!emailsToName.has(contributor.email)) {
                    emailsToName.set(contributor.email, new Set());
                }
                emailsToName.get(contributor.email).add(contributor.name || 'Anonymous');
            }
        }

        return emailsToName;
    }

    // Get events for additional intelligence
    static async getUserEvents(username, options = {}) {
        const { maxPages = 3 } = options;
        const events = [];

        for (let page = 1; page <= maxPages; page++) {
            const url = `${API_URL}/users/${username}/events/public?per_page=100&page=${page}`;
            const result = await ApiUtils.call(url);

            if (!Array.isArray(result) || result.length === 0) break;
            events.push(...result);
            if (result.length < 100) break;
        }

        return events;
    }

    // Extract emails from push events
    static extractEmailsFromEvents(events) {
        const emailsToName = new Map();

        for (const event of events) {
            if (event.type === 'PushEvent' && event.payload && event.payload.commits) {
                for (const commit of event.payload.commits) {
                    if (commit.author && commit.author.email) {
                        const email = commit.author.email;
                        const name = commit.author.name || 'Unknown';

                        if (!emailsToName.has(email)) {
                            emailsToName.set(email, new Set());
                        }
                        emailsToName.get(email).add(name);
                    }
                }
            }
        }

        return emailsToName;
    }

    // Batch fetch multiple user profiles in parallel
    static async batchGetUserProfiles(usernames, options = {}) {
        const { concurrency = 5 } = options;
        const urls = usernames.map(u => `${API_URL}/users/${u}`);
        return await parallelRequests(urls, { concurrency });
    }

    // Get repository details with more metadata
    static async getRepositoriesDetailed(username, options = {}) {
        const { includeLanguages = false } = options;
        const repos = [];
        let page = 1;

        while (true) {
            const url = `${API_URL}/users/${username}/repos?per_page=100&page=${page}&sort=pushed&direction=desc`;
            const result = await ApiUtils.call(url);

            if (!Array.isArray(result) || result.length === 0) break;

            // Add full repo data instead of just name/fork
            repos.push(...result.map(repo => ({
                name: repo.name,
                full_name: repo.full_name,
                fork: repo.fork,
                archived: repo.archived,
                disabled: repo.disabled,
                pushed_at: repo.pushed_at,
                created_at: repo.created_at,
                updated_at: repo.updated_at,
                stargazers_count: repo.stargazers_count,
                watchers_count: repo.watchers_count,
                forks_count: repo.forks_count,
                open_issues_count: repo.open_issues_count,
                language: repo.language,
                default_branch: repo.default_branch,
                description: repo.description,
                has_issues: repo.has_issues,
                size: repo.size
            })));

            if (result.length < 100) break;
            page++;
        }

        return repos;
    }

    // Search commits across all GitHub (requires auth for best results)
    static async searchCommits(query, options = {}) {
        const { maxResults = 100 } = options;
        const url = `${API_URL}/search/commits?q=${encodeURIComponent(query)}&per_page=${Math.min(maxResults, 100)}`;
        const result = await ApiUtils.call(url);

        if (result.error || !result.items) return [];
        return result.items;
    }

    // Get starred repos (can reveal interests/affiliations)
    static async getUserStarred(username, options = {}) {
        const { maxPages = 2 } = options;
        const starred = [];

        for (let page = 1; page <= maxPages; page++) {
            const url = `${API_URL}/users/${username}/starred?per_page=100&page=${page}`;
            const result = await ApiUtils.call(url);

            if (!Array.isArray(result) || result.length === 0) break;
            starred.push(...result);
            if (result.length < 100) break;
        }

        return starred;
    }

    // Get followers/following for network analysis
    static async getUserNetwork(username, options = {}) {
        const { maxFollowers = 100, maxFollowing = 100 } = options;

        const [followers, following] = await Promise.all([
            ApiUtils.call(`${API_URL}/users/${username}/followers?per_page=${maxFollowers}`),
            ApiUtils.call(`${API_URL}/users/${username}/following?per_page=${maxFollowing}`)
        ]);

        return {
            followers: Array.isArray(followers) ? followers : [],
            following: Array.isArray(following) ? following : []
        };
    }

    // Organization methods
    static async getOrganization(orgName) {
        return await ApiUtils.call(`${API_URL}/orgs/${orgName}`);
    }

    static async getOrganizationMembers(orgName) {
        return await ApiUtils.call(`${API_URL}/orgs/${orgName}/members?per_page=100`);
    }

    static async getOrganizationRepos(orgName) {
        return await ApiUtils.call(`${API_URL}/orgs/${orgName}/repos?per_page=100`);
    }

    static async getRepoCommits(orgName, repoName, page = 1) {
        return await ApiUtils.call(`${API_URL}/repos/${orgName}/${repoName}/commits?per_page=100&page=${page}`);
    }

    // Get README content (can contain contact info)
    static async getRepoReadme(owner, repo) {
        const url = `${API_URL}/repos/${owner}/${repo}/readme`;
        const result = await ApiUtils.call(url);

        if (result.error || !result.content) return null;

        // Decode base64 content
        try {
            return Buffer.from(result.content, 'base64').toString('utf-8');
        } catch {
            return null;
        }
    }

    // Extract emails from README content
    static extractEmailsFromText(text) {
        const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
        const matches = text.match(emailRegex) || [];
        return [...new Set(matches)]; // deduplicate
    }
}

module.exports = GitHubApi;