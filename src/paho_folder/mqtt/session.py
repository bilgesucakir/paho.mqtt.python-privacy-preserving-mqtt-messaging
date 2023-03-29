#bilgesu: new classs for session following
class Session():

    def __init__(self, client_id) -> None:
        self.public_key: bytes = None
        self.private_key: bytes = None
        self.session_key: bytes = None
        self.key_establishment_state: int = 0
        self.client_id: str = client_id


#properties will be added
    
