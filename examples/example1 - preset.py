import tls_client

# You can also use other `client_identifier` values.
# For the complete and up-to-date list, see `tls_client/settings.py` (`ClientIdentifiers`).

session = tls_client.Session(
    client_identifier="chrome_112",
    random_tls_extension_order=True
)

res = session.get(
    "https://www.example.com/",
    headers={
        "key1": "value1",
    },
    proxy="http://user:password@host:port"
)
