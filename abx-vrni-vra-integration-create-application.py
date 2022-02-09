# vRealize Automation Cloud integration with vRealize Network Insight
#
# This script can be run as an Extensibility Action in vRA Cloud Assembly and
# will create the deployment as an application in vRealize Network Insight Cloud.
#
# This is specifically designed for the Cloud versions of the products, the the APIs
# are the same for on-prem. The only change required is the way of authentication.
#
# Steps:
#  - Cloud Assembly -> Extensibility -> Library -> Actions: add Python action.
#     - Create action constant (type secret) named 'vrni-csp-api-token' and add a
#       CSP API token which is a: vRNI Cloud Member and Cloud Assembly Viewer
#     - Add the action constant as a default input
#     - Dependency: requests
#  - Cloud Assembly -> Extensibility -> Subscriptions: new subscription
#     - Event topic: Deployment completed
#     - Action/workflow: the action you created in the previous step
#     - You can also limit the subscription to specific cloud templates, projects, or
#       other things (check out the Condition field)
#  - Deploy something and watch the action create the vRNI application!
#
# Martijn Smit (@smitmartijn)
# msmit@vmware.com
# Version 1.0
#
# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import json
import requests
import logging

vraUrl = "https://api.mgmt.cloud.vmware.com/"


# get access token from CSP
def csp_get_token(refresh_token):
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    url = 'https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize'
    payload = {"refresh_token": refresh_token}
    response = requests.post(url, data=payload, headers=headers)
    print(response.content)
    if response.status_code != 200:
        raise Exception('[?] Unexpected Error: [HTTP {0}]: Content: {1}'.format(
            response.status_code, response.content))

    data = json.loads(response.content)
    return data["access_token"]


# get access token from vRA
def vra_get_bearer_token(refresh_token):
    # generate bearer token
    print('Generating Bearer Token for vRA Cloud...')
    body = {
        "refreshToken": refresh_token
    }
    response = requests.post(
        'https://api.mgmt.cloud.vmware.com/iaas/api/login?apiVersion=2019-01-15', data=json.dumps(body))
    if response.status_code != 200:
        raise Exception('[?] Unexpected Error: [HTTP {0}]: Content: {1}'.format(
            response.status_code, response.content))

    vraBearerToken = response.json()['token']
    bearer = "Bearer "
    bearer = bearer + vraBearerToken
    return bearer


# get the deployment information (name + resources/VMs) from the vRA APIs
def vra_get_deployment_info(vraBearerToken, deploymentId):
    # application_info[tier_name] = ['vm1','vm2','etc']
    application_info = {}
    application_name = ""
    # request the deployment details (inc resources) from vRA
    headers = {"Accept": "application/json",
               "Content-Type": "application/json", "Authorization": vraBearerToken}
    deploymentUrl = vraUrl + 'deployment/api/deployments/' + deploymentId + \
        '?expandProject=true&expandResources=true&apiVersion=2019-01-15'
    response = requests.get(deploymentUrl, data='', headers=headers)
    if response.status_code != 200:
        raise Exception('[?] Unexpected Error: [HTTP {0}]: Content: {1}'.format(
            response.status_code, response.content))

    # go through the response. the 'resources' field will be a list of deployed resources for this deployment
    # and we want to remember the VM names and the tier names of the Cloud.Machines.
    response_json = response.json()
    application_name = response_json['name']
    print("Deployment Name: " + application_name + "\n")
    for resource in response_json['resources']:
        if resource['type'] == "Cloud.Machine":
            tier_name = resource['properties']['name']
            vm_name = resource['properties']['resourceName']
            print("Found VM:\n")
            print("VM: " + vm_name + "\n")
            print("Tier: " + tier_name + "\n")

            if tier_name in application_info:
                application_info[tier_name].append(vm_name)
            else:
                application_info[tier_name] = []
                application_info[tier_name].append(vm_name)
    return application_name, application_info


# create the vRNI application construct and add the tiers after
def vrni_create_app(application_name, application_info, auth_token):
    headers = {"Accept": "application/json",
               "Content-Type": "application/json", "csp-auth-token": auth_token}

    # first create application container and get its entity ID
    body = {
        "name": application_name
    }

    app_id = ""
    response = requests.post(
        'https://api.mgmt.cloud.vmware.com/ni/api/ni/groups/applications', data=json.dumps(body), headers=headers)
    if response.status_code != 200 and response.status_code != 201:
        raise Exception('[?] Unexpected Error: [HTTP {0}]: Content: {1}'.format(
            response.status_code, response.content))

    print("Created vRNI application: " + application_name)
    response_json = response.json()
    app_id = response_json['entity_id']

    # now create the tiers
    # application_info[tier_name] = ['vm1','vm2','etc']
    for tier_name, vm_list in application_info.items():
        vm_list_search = "','".join(vm_list)

        # format vRNI API call
        body = {
            "name": tier_name,
            "group_membership_criteria": [{
                "membership_type": "SearchMembershipCriteria",
                "search_membership_criteria": {
                    "entity_type": "BaseVirtualMachine",
                    "filter": "name in('" + vm_list_search + "')"
                }
            }]
        }

        response = requests.post('https://api.mgmt.cloud.vmware.com/ni/api/ni/groups/applications/' +
                                 app_id+'/tiers', data=json.dumps(body), headers=headers)
        if response.status_code != 200 and response.status_code != 201:
            raise Exception('[?] Unexpected Error: [HTTP {0}]: Content: {1}'.format(
                response.status_code, response.content))

        print("Added vRNI Tier: " + tier_name)


# main handler, is run by vRA
def handler(context, inputs):
    # automatically is added when the subscription runs
    deploymentId = inputs['deploymentId']
    # create a secret with the CSP API token and name it: vrni-csp-api-token
    refresh_token = context.getSecret(inputs["vrni-csp-api-token"])

    # retrieve the vRA bearer token - we need this before we can do other API calls
    vraBearerToken = vra_get_bearer_token(refresh_token)
    # get the deployment name and resource info (VM list)
    application_name, application_info = vra_get_deployment_info(
        vraBearerToken, deploymentId)

    # retrieve the CSP auth token - we need this before we can do other API calls against vRNI Cloud
    auth_token = csp_get_token(refresh_token)
    # create the vRNI apps!
    vrni_create_app(application_name, application_info, auth_token)

    outputs = {
        "check_log": "no_output_here"
    }

    return outputs
