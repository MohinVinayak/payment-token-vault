import pytest
from fastapi.testclient import TestClient
from app.main import app


client = TestClient(app)

def test_tokenize_success():

    response = client.post(
        "/tokenize",
        json={"card_number": "4242424242424242"}
    )
    
   
    assert response.status_code == 200
    
  
    data = response.json()
    assert "token" in data
    assert data["masked_pan"] == "************4242"

def test_detokenize_forbidden():
    # 1. Send the POST request WITHOUT the admin header
    response = client.post(
        "/detokenize",
        json={
            "token": "kXp1s9_VbLm3qE8zA-cWgY2t", 
            "reason": "automated security test"
        }
    )
    
    # 2. Check that the server blocks it with a 403 Forbidden
    assert response.status_code == 403
    
    # 3. (Optional but good) Verify the exact error message matches
    assert response.json()["detail"] == "Admin access required"