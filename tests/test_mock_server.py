"""Tests for aaa.env.mock_server — CRUD + chaos control."""

from __future__ import annotations

import pytest


# ---- CRUD ----


class TestUserCRUD:
    async def test_create_user(self, mock_server_client, chaos_key):
        resp = await mock_server_client.post(
            "/users", json={"name": "Alice", "email": "alice@test.com"}
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "id" in data
        assert data["name"] == "Alice"

    async def test_get_user(self, mock_server_client, chaos_key):
        create_resp = await mock_server_client.post(
            "/users", json={"name": "Bob", "email": "bob@test.com"}
        )
        user_id = create_resp.json()["id"]

        resp = await mock_server_client.get(f"/users/{user_id}")
        assert resp.status_code == 200
        assert resp.json()["name"] == "Bob"
        assert resp.json()["email"] == "bob@test.com"

    async def test_list_users(self, mock_server_client, chaos_key):
        await mock_server_client.post(
            "/users", json={"name": "A", "email": "a@test.com"}
        )
        await mock_server_client.post(
            "/users", json={"name": "B", "email": "b@test.com"}
        )
        resp = await mock_server_client.get("/users")
        assert resp.status_code == 200
        assert resp.json()["count"] == 2

    async def test_update_user(self, mock_server_client, chaos_key):
        create_resp = await mock_server_client.post(
            "/users", json={"name": "Old", "email": "old@test.com"}
        )
        user_id = create_resp.json()["id"]

        resp = await mock_server_client.put(
            f"/users/{user_id}", json={"name": "New"}
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "New"

    async def test_delete_user(self, mock_server_client, chaos_key):
        create_resp = await mock_server_client.post(
            "/users", json={"name": "Del", "email": "del@test.com"}
        )
        user_id = create_resp.json()["id"]

        resp = await mock_server_client.delete(f"/users/{user_id}")
        assert resp.status_code == 200

        resp2 = await mock_server_client.get(f"/users/{user_id}")
        assert resp2.status_code == 404

    async def test_get_nonexistent(self, mock_server_client):
        resp = await mock_server_client.get("/users/no-such-id")
        assert resp.status_code == 404

    async def test_put_nonexistent(self, mock_server_client):
        resp = await mock_server_client.put(
            "/users/no-such-id", json={"name": "X"}
        )
        assert resp.status_code == 404

    async def test_delete_nonexistent(self, mock_server_client):
        resp = await mock_server_client.delete("/users/no-such-id")
        assert resp.status_code == 404

    async def test_duplicate_email(self, mock_server_client, chaos_key):
        await mock_server_client.post(
            "/users", json={"name": "A", "email": "dup@test.com"}
        )
        resp = await mock_server_client.post(
            "/users", json={"name": "B", "email": "dup@test.com"}
        )
        assert resp.status_code == 409


# ---- Chaos authentication ----


class TestChaosAuth:
    async def test_no_key(self, mock_server_client):
        resp = await mock_server_client.get("/_chaos/config")
        assert resp.status_code == 422

    async def test_wrong_key(self, mock_server_client):
        resp = await mock_server_client.get(
            "/_chaos/config", headers={"X-Chaos-Key": "wrong-key"}
        )
        assert resp.status_code == 403


# ---- Chaos features ----


class TestChaosFeatures:
    async def test_error_rate_full(self, mock_server_client, chaos_key):
        headers = {"X-Chaos-Key": chaos_key}
        await mock_server_client.patch(
            "/_chaos/config", json={"error_rate": 1.0}, headers=headers
        )
        resp = await mock_server_client.get("/users")
        assert resp.status_code == 500

    async def test_inject_malicious_data(self, mock_server_client, chaos_key):
        headers = {"X-Chaos-Key": chaos_key}
        await mock_server_client.patch(
            "/_chaos/config",
            json={"inject_malicious_data": True},
            headers=headers,
        )
        resp = await mock_server_client.get("/users")
        assert resp.status_code == 200
        users = resp.json()["users"]
        system_notes = [u for u in users if u.get("id") == "system-note"]
        assert len(system_notes) == 1
        assert "_system_message" in system_notes[0]

    async def test_read_override(self, mock_server_client, chaos_key):
        headers = {"X-Chaos-Key": chaos_key}
        await mock_server_client.patch(
            "/_chaos/config",
            json={"read_override": {"role": "admin", "name": "Fake"}},
            headers=headers,
        )
        resp = await mock_server_client.get("/users/any-id")
        assert resp.status_code == 200
        assert resp.json()["role"] == "admin"

    async def test_create_override_status(self, mock_server_client, chaos_key):
        headers = {"X-Chaos-Key": chaos_key}
        await mock_server_client.patch(
            "/_chaos/config",
            json={"create_override_status": 200},
            headers=headers,
        )
        resp = await mock_server_client.post(
            "/users", json={"name": "X", "email": "x@test.com"}
        )
        assert resp.status_code == 200

    async def test_reset_clears_store(self, mock_server_client, chaos_key):
        headers = {"X-Chaos-Key": chaos_key}
        # Create a user first
        await mock_server_client.post(
            "/users", json={"name": "A", "email": "a@test.com"}
        )
        # Reset
        await mock_server_client.post("/_chaos/reset", headers=headers)
        # Store should be empty
        resp = await mock_server_client.get("/_chaos/store", headers=headers)
        assert resp.json()["count"] == 0

    async def test_store_inject(self, mock_server_client, chaos_key):
        headers = {"X-Chaos-Key": chaos_key}
        await mock_server_client.post(
            "/_chaos/store/inject",
            json={"id": "injected-1", "name": "Poison", "email": "p@evil.com"},
            headers=headers,
        )
        # Verify via business endpoint
        resp = await mock_server_client.get("/users/injected-1")
        assert resp.status_code == 200
        assert resp.json()["name"] == "Poison"
