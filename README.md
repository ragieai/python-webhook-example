## Python-webhook-example

This is a very simple app to illustrate how to verify the signature of webhooks dispatched by Ragie.

It uses poetry as its python package manager.

### Instructions
1. Clone this repo
2. Navigate to the directory you cloned to
3. Run `poetry install`
4. Run `poetry run uvicorn ragie_webhook_ref_app.main:app --reload --port <DESIRED_PORT_NUMBER>`
5. Expose the app on the internet using something like [ngrok](https://ngrok.com/) or [port forwarding in vscode](https://code.visualstudio.com/docs/editor/port-forwarding)
6. Log into your Ragie instance, click webhooks and add an endpoint using the web exposed URL
7. Click test and select the event type you'd like to test
