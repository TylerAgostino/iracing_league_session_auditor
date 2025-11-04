# iRacing League Session Auditor

A tool to validate and audit iRacing league sessions against expected parameters. This utility helps league administrators ensure that their racing sessions are configured correctly and consistently.

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

# Run with command-line arguments
docker run -v $(pwd)/expectations.json:/app/expectations.json -v $(pwd)/data:/data iracing_league_session_auditor --username "your_iracing_email" --password "your_iracing_password" --league-id 12345
```

## Usage

### Command Line
```bash
iracing-audit --username "your_iracing_email" --password "your_iracing_password" --league-id 12345 --expectations-path "expectations.json"
```
Windows may require using `iracing-audit.exe` instead of `iracing-audit`.

Or directly with:
```bash
python -m iracing_league_session_auditor --username "your_iracing_email" --password "your_iracing_password" --league-id 12345 --expectations-path "expectations.json"
```

### Options

- `--username`: iRacing account email (required)
- `--password`: iRacing account password (required)
- `--league-id`: iRacing league ID (required)
- `--expectations-path`: Path to the JSON file containing expectations (default: "expectations.json")
- `--state-path`: Path to the JSON file for storing state (default: "state.json")
- `--webhook-url`: URL of the webhook to send results to (optional)
- `--keep-alive`: Keep the application running to monitor changes (default: false)
- `--interval`: Interval in minutes to re-run the validation when keep-alive is enabled (default: 60)
- `--force`: Force re-validation of all sessions, even if they haven't changed

### Docker Compose

A sample docker-compose.yaml is included in the repository:

```bash
# Create and configure your environment file
cp .env.example .env
# Edit the .env file with your credentials

# Run with Docker Compose
docker-compose up -d
```

The Docker Compose setup:
- Mounts your expectations.json file into the container
- Creates a persistent volume for the state.json file
- Uses environment variables from your .env file
- Runs as a service that can be restarted automatically



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
# Required variables
IRACING_USERNAME=your_iracing_email@example.com
IRACING_PASSWORD=your_iracing_password
LEAGUE_ID=8579

# Optional variables
WEBHOOK_URL=https://discord.com/api/webhooks/your_webhook_url
```

A `.env.example` file is included in the repository. Copy it to `.env` and update with your credentials:

```bash
cp .env.example .env
```

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
