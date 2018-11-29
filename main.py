# -*- coding: utf-8 -*-

import os
import json
from flask import Flask, session, redirect, url_for, request, jsonify

from datetime import date, datetime
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

# The CLIENT_SECRETS_FILE variable specifies the name of a file that contains
# the OAuth 2.0 information for this application, including its client_id and
# client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = ['https://www.googleapis.com/auth/youtube.force-ssl','https://www.googleapis.com/auth/youtube']
API_SERVICE_NAME = 'youtube'
API_VERSION = 'v3'

app = Flask(__name__)
# Note: A secret key is included in the sample so that it works, but if you
# use this code in your application please replace this with a truly secret
# key. See http://pocoo.org/docs/0.12/quickstart/#sessions.
app.secret_key = 'REPLACE ME - this value is here as a placeholder.'

# Remove keyword arguments that are not set
def remove_empty_kwargs(**kwargs):
    good_kwargs = {}
    if kwargs is not None:
        for key, value in kwargs.items():
            if value:
                good_kwargs[key] = value
    return good_kwargs

@app.route('/')
def index():
  if 'credentials' not in session:
    return redirect('authorize')
    #Keywords = 'red dead online glitch'
    #Keywords = 'black ops 4 glitches'
    #Keywords = 'black ops 4'
    #Keywords = 'blackout glitch'
    #Keywords = 'fallout 76 glitch'
    #Keywords = 'red dead online guide'
    #Keywords = 'cwl update'
  

  return '<a href="/run/fallout glitches/">Run Fallout Glitches</a><a href="/run/red dead online glitch/">Run Red Dead Online Glitch</a></br>'

@app.route('/run/<string:search>/')
def run(search):
  
  if 'credentials' not in session:
    return redirect('authorize')

  run_script(search)

  return 'Script Processed: ' + search

@app.route('/authorize')
def authorize():
  # Create a flow instance to manage the OAuth 2.0 Authorization Grant Flow
  # steps.
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)
  flow.redirect_uri = url_for('oauth2callback', _external=True)
  print(flow)
  authorization_url, state = flow.authorization_url(
      # This parameter enables offline access which gives your application
      # both an access and refresh token.
      access_type='offline',
      # This parameter enables incremental auth.
      include_granted_scopes='true')

  # Store the state in the session so that the callback can verify that
  # the authorization server response.
  session['state'] = state

  return redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
  # Specify the state when creating the flow in the callback so that it can
  # verify the authorization server response.
  state = session['state']
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
  flow.redirect_uri = url_for('oauth2callback', _external=True)

  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = request.url
  
  flow.fetch_token(authorization_response=authorization_response)
  # Store the credentials in the session.
  # ACTION ITEM for developers:
  #     Store user's access and refresh tokens in your data store if
  #     incorporating this code into your real app.
  credentials = flow.credentials
  session['credentials'] = {
      'token': credentials.token,
      'refresh_token': credentials.refresh_token,
      'token_uri': credentials.token_uri,
      'client_id': credentials.client_id,
      'client_secret': credentials.client_secret,
      'scopes': credentials.scopes
  }

  return redirect(url_for('index'))

def run_script(Keywords):
  # Load the credentials from the session.
  credentials = google.oauth2.credentials.Credentials(
      **session['credentials'])

  client = googleapiclient.discovery.build(
      API_SERVICE_NAME, API_VERSION, credentials=credentials)


  searchList = search_list_by_keyword(client,
                          part='snippet',
                          maxResults=50,
                          q=Keywords,
                          type='video',
                          publishedAfter=str(date.today()) + 'T00:00:00Z'
                          #publishedAfter=str(date.today() - timedelta(days=30)) + 'T00:00:00Z'
                          )

  channelIDs = getChannelIds(searchList)
  videoIDs = getVideoIds(searchList)
  
  channels_list_by_id(client,
      part='statistics',
      id=channelIDs)

  videos_list_by_id(client,
      part='contentDetails,statistics',
      id=videoIDs)

  return 'worked!'

def channels_list_by_username(client, **kwargs):
  response = client.channels().list(
    **kwargs
  ).execute()

  return jsonify(**response)

def search_list_by_keyword(client, **kwargs):
    # See full sample for function
    kwargs = remove_empty_kwargs(**kwargs)

    response = client.search().list(
        **kwargs
    ).execute()

    text_file = open("searchData.json", "w")
    text_file.write(json.dumps(response))
    text_file.close()

    return response

def getVideoIds(responses):
    result = ''
    for x in responses['items']:
        result += x['id']['videoId'] + ','
    return result[:-1]

def getChannelIds(responses):
    result = ''
    for x in responses['items']:
        result += x['snippet']['channelId'] + ','
    return result[:-1]

def channels_list_by_id(client, **kwargs):
    # See full sample for function
    kwargs = remove_empty_kwargs(**kwargs)

    response = client.channels().list(
        **kwargs
    ).execute()

    text_file = open("channelData.json", "w")
    text_file.write(json.dumps(response))
    text_file.close()

    return response

def videos_list_by_id(client, **kwargs):
    # See full sample for function
    kwargs = remove_empty_kwargs(**kwargs)

    response = client.videos().list(
        **kwargs
    ).execute()

    text_file = open("videoData.json", "w")
    text_file.write(json.dumps(response))
    text_file.close()

    return response

if __name__ == '__main__':
  # When running locally, disable OAuthlib's HTTPs verification. When
  # running in production *do not* leave this option enabled.
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
  app.run('localhost', 80, debug=True)