# Integrations between vRealize Network Insight Cloud & vRealize Automation Cloud

## Creating vRNI Applications on vRA Deployments

[abx-vrni-vra-integration-create-application.py](https://github.com/vrealize-network-insight/vrni-vra-integration/blob/main/abx-vrni-vra-integration-create-application.py)

This script can be run as an Extensibility Action in vRA Cloud Assembly and
will create the deployment as an application in vRealize Network Insight Cloud.

This is specifically designed for the Cloud versions of the products, but the APIs
are the same for on-prem. The only change required is the way of authentication.

Steps:

- Cloud Assembly -> Extensibility -> Library -> Actions: add Python action.
  - Create action constant (type secret) named 'vrni-csp-api-token' and add a
    CSP API token which is a: vRNI Cloud Member and Cloud Assembly Viewer
  - Add the action constant as a default input
  - Dependency: requests
- Cloud Assembly -> Extensibility -> Subscriptions: new subscription
  - Event topic: Deployment completed
  - Action/workflow: the action you created in the previous step
  - You can also limit the subscription to specific cloud templates, projects, or
    other things (check out the Condition field)
- Deploy something and watch the action create the vRNI application!

![Extensibility Action Creation](https://github.com/vrealize-network-insight/vrni-vra-integration/blob/main/docs/vra-abx-vrni-apps.png?raw=true)
*Extensibility Action Creation*

![Subscribing the ABX to Deployments](https://github.com/vrealize-network-insight/vrni-vra-integration/blob/main/docs/vra-subscription-setup-vrni-apps.png?raw=true)
*Subscribing the ABX to Deployments*
