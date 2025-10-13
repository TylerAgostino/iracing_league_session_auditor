import requests
import logging

log = logging.getLogger(__name__)


class Notifier:
    def __init__(self, webhook_url: str):
        self.webhook_url: str = webhook_url

    def send_notification(self, payload: dict[str, str | dict[str, str | int]]):
        # Placeholder for sending notification logic
        log.info(f"Sending notification to {self.webhook_url}: {payload}")
        headers = {"Content-Type": "application/json"}
        wh_response = requests.post(self.webhook_url, json=payload, headers=headers)
        if wh_response.status_code == 204:
            log.info("Results sent to Discord successfully.")
        else:
            log.error(
                f"Failed to send results to Discord: {wh_response.status_code} - {wh_response.text}"
            )
        return wh_response
