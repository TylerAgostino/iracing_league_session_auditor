import requests
import json

class Notifier:
    def __init__(
            self,
            webhook_url: str,
            state_path: str
    ):
        self.webhook_url = webhook_url
        self.state_path = state_path

    def send_notification(self, payload: str):
        # Placeholder for sending notification logic
        print(f"Sending notification to {self.webhook_url}: {payload}")
        headers = {"Content-Type": "application/json"}
        wh_response = requests.post(
            self.webhook_url, json=payload, headers=headers
        )
        if wh_response.status_code == 204:
            print("Results sent to Discord successfully.")
        else:
            print(
                f"Failed to send results to Discord: {wh_response.status_code} - {wh_response.text}"
            )
        return wh_response

    def state_changed(self, new_state: dict) -> bool:
        try:
            with open(self.state_path, 'r') as f:
                current_state = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            current_state = {}

        new_state = self.sort_state_object(new_state)
        current_state = self.sort_state_object(current_state)

        return new_state != current_state

    def update_state(self, new_state: dict) -> None:
        new_state = self.sort_state_object(new_state)
        file_contents = json.dumps(new_state, indent=4)
        with open(self.state_path, 'w') as f:
            f.write(file_contents)
        return

    def sort_state_object(self, state_obj: dict) -> dict:
        return {k: self.sort_state_object(v) if isinstance(v, dict) else v for k, v in sorted(state_obj.items())}