// Global configuration for self-hosted Renovate.
// The list of repositories comes from ../repos.json - the single place where repos are added or removed.
const fs = require('fs');

const { repos } = JSON.parse(fs.readFileSync('/config/repos.json', 'utf8'));

module.exports = {
  platform: 'github',
  repositories: repos.filter((r) => r.renovate !== false).map((r) => r.repo),

  // Repositories don't need their own renovate.json - this config is enough.
  // If a repository has one, its settings take precedence.
  onboarding: false,
  requireConfig: 'optional',

  gitAuthor: process.env.RENOVATE_GIT_AUTHOR || 'security-watch <security-watch@users.noreply.github.com>',
  binarySource: 'install', // Renovate installs composer/node/python/... on demand
  timezone: process.env.RENOVATE_TIMEZONE || 'UTC',

  // --- defaults for all repositories ---
  extends: ['config:recommended', ':dependencyDashboard'],
  labels: ['dependencies'],
  prHourlyLimit: 4,
  prConcurrentLimit: 10,

  // Regular updates only at night on weekdays, grouped into a single PR per repo.
  schedule: ['before 7am every weekday'],
  packageRules: [
    {
      matchUpdateTypes: ['minor', 'patch', 'pin', 'digest'],
      groupName: 'non-major dependencies',
      groupSlug: 'non-major',
    },
    {
      // Major versions only after approval in the "Dependency Dashboard" issue.
      matchUpdateTypes: ['major'],
      dependencyDashboardApproval: true,
    },
  ],

  // Security fixes: immediately, outside the schedule, each as a separate PR.
  osvVulnerabilityAlerts: true,
  vulnerabilityAlerts: {
    labels: ['security', 'dependencies'],
  },
};
