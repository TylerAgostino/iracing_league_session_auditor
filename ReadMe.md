# iRacing League Session Auditor

A tool to validate and audit iRacing league sessions against expected parameters. This utility helps league administrators ensure that their racing sessions are configured correctly and consistently.

> **⚠️ IMPORTANT: OAuth 2.1 Authentication Required**
> 
> This tool now uses OAuth 2.1 authentication. The old username/password method has been deprecated by iRacing.
> 
> - **For CLI use with browser:** No registration needed! Works out of the box.
> - **For Docker/headless:** You must register with iRacing. See the [OAuth Migration Guide](OAuth_Migration_Guide.md).

## Features

- Validates iRacing league sessions against predefined expectations
- Monitors sessions for changes and only re-validates when needed
- Supports advanced validation rules including time-based scheduling with cron expressions
- Sends notifications via webhooks when validation fails
- State tracking to avoid redundant validations
- Docker support for containerized deployment

## Installation

### Using pip

```bash
pip install iracing_league_session_auditor
```

### From source

```bash
git clone https://github.com/TylerAgostino/iracing_league_session_auditor.git
cd iracing_league_session_auditor
pip install -e .
```

### Using Docker

```bash
# Build the Docker image
docker build -t iracing_league_session_auditor .

# Run with command-line arguments (Password Limited Flow)
docker run \
  -e IRACING_CLIENT_ID="your_client_id" \
  -e IRACING_CLIENT_SECRET="your_client_secret" \
  -e IRACING_USERNAME="your_email@example.com" \
  -e IRACING_PASSWORD="your_password" \
  -e IRACING_USE_PASSWORD_FLOW="true" \
  -v $(pwd)/expectations.json:/app/expectations.json \
  -v $(pwd)/data:/data \
  iracing_league_session_auditor --league-id 12345
```

## Usage

### Prerequisites

**For CLI with Browser (Authorization Code Flow):**
- No prerequisites! Uses default `client_id='session-auditor'` - works out of the box.

**For Headless/Docker (Password Limited Flow):**
1. **MUST** register an OAuth client with iRacing
2. Obtain your **custom** `client_id` and `client_secret`
3. Register your username with iRacing for Password Limited Flow (max 3 users)
4. **Important:** Password Limited Flow requires a custom client_id - the default `session-auditor` cannot be used

See the [OAuth Migration Guide](OAuth_Migration_Guide.md) for detailed instructions.

### Command Line (Interactive with Browser)

```bash
# No configuration needed! Just run:
iracing-audit --league-id 12345 --expectations-path "expectations.json"
```

The tool will open your browser for secure authentication. It uses these defaults:
- `client_id='session-auditor'`
- `redirect_uri='http://127.0.0.1:0/callback'` (random available port)
- `audience='data-server'`

### Command Line (Headless/Password Flow)

```bash
# Set environment variables (credentials via environment only for security)
# MUST use YOUR custom client_id from iRacing, NOT 'session-auditor'
export IRACING_CLIENT_ID="your_custom_client_id"  # From iRacing registration
export IRACING_CLIENT_SECRET="your_client_secret"  # From iRacing registration
export IRACING_USERNAME="your_email@example.com"
export IRACING_PASSWORD="your_password"
export IRACING_USE_PASSWORD_FLOW="true"

# Run the tool
iracing-audit --league-id 12345 --expectations-path "expectations.json"
```

**Note:** 
- For security, username and password are only accepted via environment variables, not command-line arguments.
- Password Limited Flow requires a custom client_id obtained from iRacing - cannot use the default `session-auditor`.

Windows may require using `iracing-audit.exe` instead of `iracing-audit`.

Or directly with:
```bash
python -m iracing_league_session_auditor --league-id 12345 --expectations-path "expectations.json"
```

### Options

**OAuth Credentials:**
- `--client-id`: OAuth client ID (env: `IRACING_CLIENT_ID`) (default: `session-auditor`)
- `--client-secret`: OAuth client secret (env: `IRACING_CLIENT_SECRET`) (optional for auth code flow, required for password flow)
- `--redirect-uri`: OAuth redirect URI (env: `IRACING_REDIRECT_URI`) (default: `http://127.0.0.1:0/callback`)
- `--use-password-flow`: Use Password Limited Flow instead of browser-based auth (env: `IRACING_USE_PASSWORD_FLOW`)

**Password Limited Flow (Headless Only):**
- Username and password must be set via environment variables `IRACING_USERNAME` and `IRACING_PASSWORD` (not available as command-line arguments for security)

**General Options:**
- `--league-id`: iRacing league ID (required)
- `--expectations-path`: Path to the JSON file containing expectations (default: "expectations.json")
- `--state-path`: Path to the JSON file for storing state (default: "state.json")
- `--webhook-url`: URL of the webhook to send results to (optional)
- `--keep-alive`: Keep the application running to monitor changes (default: false)
- `--interval`: Interval in seconds to re-run the validation when keep-alive is enabled (default: 3600)
- `--force`: Force re-validation of all sessions, even if they haven't changed

### Docker Compose

A sample docker-compose.yaml is included in the repository:

```bash
# Create and configure your environment file
cp .env.example .env
# Edit the .env file with your OAuth credentials

# Run with Docker Compose
docker-compose up -d
```

The Docker Compose setup:
- Mounts your expectations.json file into the container
- Creates a persistent volume for the state.json file
- Uses environment variables from your .env file (including OAuth credentials)
- Runs as a service that can be restarted automatically
- Uses Password Limited Flow for headless operation



## Configuration

### Expectations File

The expectations file is a JSON document that defines the expected configuration for your league sessions. Each entry in the expectations array represents a different session type that might be found in your league.

Example:

```json
[
  {
    "name": "NASCAR Trucks",
    "expectation": {
      "cars": [
        {
          "car_id": 123,
          "car_name": "NASCAR Truck Ford F150",
          "car_class_id": 0
        }
      ],
      "launch_at": { "cron": "30 0 * * 4", "margin": 15 },
      "max_drivers": { "operator": ">", "value": 20 },
      "league_id": 8579,
      "practice_length": 20,
      "qualify_length": 20,
      "race_length": 20
    }
  }
]
```

If there is no expectations file, the tool will create one using the first session it finds in the league. This can be useful for initial setup.

### Cron Expressions for Session Scheduling

The tool supports validating session start times using cron expressions with a margin of error in minutes:

```
"launch_at": { "cron": "30 0 * * 4", "margin": 15 }
```

This example expects sessions to start at 00:30 on Thursdays with a 15-minute margin. 

For whatever reason, Python has to be different and uses different numbers for the days of the week in cron expressions. This is dumb, and I choose to use unix style instead. So, in this case, 0 = Sunday, 1 = Monday, ..., 6 = Saturday.

### State File

The state file tracks session states to avoid unnecessary revalidation. This file is managed automatically by the tool. You can force revalidation of all sessions using the `--force` flag.

### Environment Variables

When using Docker or Docker Compose, you can configure the application using environment variables:

```
# OAuth Credentials for Password Limited Flow (Required for headless/Docker)
IRACING_CLIENT_ID=your_custom_client_id  # From iRacing registration
IRACING_CLIENT_SECRET=your_client_secret  # From iRacing registration
IRACING_USE_PASSWORD_FLOW=true
IRACING_USERNAME=your_iracing_email@example.com
IRACING_PASSWORD=your_iracing_password

# League Configuration (Required)
LEAGUE_ID=8579

# Optional variables
WEBHOOK_URL=https://discord.com/api/webhooks/your_webhook_url
```

A `.env.example` file is included in the repository. Copy it to `.env` and update with your credentials:

```bash
cp .env.example .env
```

**Note:** For headless/Docker deployments, you must use Password Limited Flow and your username must be pre-registered with iRacing for this authentication method.

## Authentication

The tool supports two OAuth 2.1 authentication methods:

1. **Authorization Code Flow (CLI with Browser)** 
   - For interactive use, opens a browser for secure login
   - **No registration required** - uses default `client_id='session-auditor'`
   - Works out of the box

2. **Password Limited Flow (Headless/Docker)** 
   - For automated/service deployments without browser access
   - **Requires registration with iRacing** to obtain custom client credentials
   - Username must be pre-approved (max 3 users per client)
   - **Must use custom client_id** - the default `session-auditor` cannot be used for this flow

For detailed information about authentication setup and migration from the old system, see the [OAuth Migration Guide](OAuth_Migration_Guide.md).

## Notifications

When validation fails, the tool can send notifications to a webhook URL. This is currently only implemented for [Discord webhooks](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks)

## Development

### Requirements

- Python 3.8+
- Development dependencies: pytest, black, flake8, mypy

### Setup Development Environment

```bash
# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"
```
