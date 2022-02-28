example
=======
Synchronous API Wrapper::

    import researchmap

    def main():

      with open('env/rmap_jwt_private.key', 'rb') as f_private:
        private_key = f_private.read()
      with open('env/rmap_client_id.key', 'r') as f_id:
        id = f_id.read()
      client_id = id
      client_secret = private_key
      scope = 'read researchers'
      auth = researchmap.Auth(client_id, client_secret, scope)
      access_token = auth.get_access_token()["access_token"]
      req = researchmap.RequestsAdapter(access_token)
      payload = {"format": "json", "limit": 100, "institution_code": "所属機関の機関コード"}
      print(req.get_bulk(payload))

    if __name__ == "__main__":
      main()

