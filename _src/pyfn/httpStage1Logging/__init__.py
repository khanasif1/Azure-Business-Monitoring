import logging

import azure.functions as func
import requests
import hashlib
import hmac
import base64
import urllib3
import json
import datetime

table_name = 'BusinessLogsFlow'

azure_log_customer_id = ''
azure_log_shared_key = ''


def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    """Returns authorization header which will be used when sending data into Azure Log Analytics"""

    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + \
        str(content_length) + "\n" + content_type + \
        "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, 'UTF-8')
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(
        decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode('utf-8')
    authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
    return authorization


def say_hello(message):
    print(message)
    logging.info(message)


def post_data(customer_id, shared_key, body, log_type):
    """Sends payload to Azure Log Analytics Workspace

    Keyword arguments:
    customer_id -- Workspace ID obtained from Advanced Settings
    shared_key -- Authorization header, created using build_signature
    body -- payload to send to Azure Log Analytics
    log_type -- Azure Log Analytics table name
    """

    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

    content_length = len(body)
    signature = build_signature(
        customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)

    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + \
        resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri, data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        logging.info('Accepted payload:' + body)
        print('Accepted payload:' + body)
        print('Response status code: ' + str(response.status_code))
        print('Response status message: ' + str(response.reason))
        print('Response headers: ' + str(response.headers))
        print("Message posted to Log Analytics WS")
    else:
        logging.error("Unable to Write: " + format(response.status_code))


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    corelationId = req.params.get('corelationId')
    if not corelationId:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            corelationId = req_body.get('corelationId')

    data = {
        "corelationId": corelationId,
        "state": "failed",
        "logtype":  "business flow log",
        "message": "Business Monitor : Py Function Posted " + datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    }

    data_json = json.dumps(data)
    logging.info(f'CorelationId extracted: {corelationId}')
    try:
        say_hello(f" sayhello CorelationId extracted: {corelationId}")
        post_data(azure_log_customer_id,
                  azure_log_shared_key, data_json, table_name)
    except Exception as error:
        logging.error("Unable to send data to Azure Log")
        logging.error(error)
    if corelationId:
        return func.HttpResponse(f"CorelationId, {corelationId}. This HTTP triggered function executed successfully.")
    else:
        return func.HttpResponse(
            "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
            status_code=200
        )
