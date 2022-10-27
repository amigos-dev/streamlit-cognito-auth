

import streamlit as st
from streamlit_cognito_auth import cognito_auth
import json

auth = cognito_auth().update()

auth.button()

st.write(f"ID token payload={json.dumps(auth.id_token_payload)}")
st.write(f"user_info={json.dumps(auth.get_user_info())}")

auth.require_verified()

st.info(f"Yay! You are logged in to verified email address {auth.user_email}, and are in these Cognito groups: {auth.cognito_groups}")
