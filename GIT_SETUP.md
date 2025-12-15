# Git Setup Instructions

This guide will help you initialize and push this project to a Git repository.

## Step 1: Initialize Git Repository

```bash
# Navigate to the project directory
cd /Users/charafachir/projects/cybersec

# Initialize git repository
git init

# Check status
git status
```

## Step 2: Add All Files

```bash
# Add all files (respecting .gitignore)
git add .

# Verify what will be committed
git status
```

## Step 3: Create Initial Commit

```bash
# Create initial commit
git commit -m "Initial commit: S2-045 Defense & Exploitation Lab

- Vulnerable Struts 2.3.31 application for exploitation demo
- Patched Struts 6.3.x application with WAF protection
- Exploitation tools and scripts
- Comprehensive documentation
- Docker Compose setup for easy deployment"
```

## Step 4: Create Remote Repository

### Option A: GitHub (Recommended)

1. Go to https://github.com/new
2. Create a new repository (e.g., `cybersec` or `struts2-s2-045-lab`)
3. **Do NOT** initialize with README, .gitignore, or license (we already have these)
4. Copy the repository URL

### Option B: GitLab

1. Go to https://gitlab.com/projects/new
2. Create a new project
3. Copy the repository URL

### Option C: Other Git Hosting

Create a repository on your preferred Git hosting service and get the URL.

## Step 5: Add Remote and Push

```bash
# Add remote repository (replace with your actual URL)
git remote add origin https://github.com/yourusername/cybersec.git

# Or if using SSH:
# git remote add origin git@github.com:yourusername/cybersec.git

# Verify remote was added
git remote -v

# Push to remote repository
git branch -M main
git push -u origin main
```

## Step 6: Verify

```bash
# Check remote status
git remote -v

# View commit history
git log --oneline

# Check branch
git branch
```

## Future Updates

After making changes:

```bash
# Check what changed
git status

# Add changes
git add .

# Commit changes
git commit -m "Description of changes"

# Push to remote
git push
```

## Important Notes

### Files Excluded by .gitignore

The following are **NOT** committed (as they should be):
- `logs/` directory (generated at runtime)
- `target/` directories (Maven build artifacts)
- IDE files (`.vscode/`, `.idea/`)
- Python cache files (`__pycache__/`)
- Temporary files

### What IS Committed

- All source code
- Dockerfiles and Docker Compose configuration
- Documentation (README, guides, glossary)
- Configuration files (nginx, struts, log4j, etc.)
- Exploit scripts
- Test scripts

## Troubleshooting

### If you get "repository not found" error:

1. Verify the repository URL is correct
2. Check that you have access to the repository
3. If using SSH, ensure your SSH key is set up: `ssh -T git@github.com`

### If you get "permission denied" error:

1. Check your Git credentials: `git config --list`
2. Update credentials if needed: `git config --global user.name "Your Name"`
3. For HTTPS, you may need a personal access token instead of password

### If you want to change the remote URL:

```bash
# View current remote
git remote -v

# Change remote URL
git remote set-url origin <new-url>

# Verify
git remote -v
```

## Security Considerations

⚠️ **Important**: This repository contains:
- Working exploit code
- Vulnerable application code
- Security testing tools

**Before pushing to a public repository:**
- Ensure you're comfortable with public disclosure
- Consider making it private if it's for educational/internal use only
- Review the repository settings and access controls

