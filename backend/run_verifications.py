import asyncio, json, sys, os
sys.path.insert(0, os.path.abspath('.'))

async def test_ws():
    try:
        import websockets
        async with websockets.connect(
            'ws://localhost:8000/api/v1/recon/ws/test-scan-123?token=dev-api-key',
            open_timeout=5
        ) as ws:
            print('WS CONNECTED')
            await asyncio.wait_for(ws.recv(), timeout=3)
    except Exception as e:
        print(f'WS FAILED: {type(e).__name__}: {e}')

async def test_redis():
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url('redis://localhost:6379/0')
        await r.ping()
        print('REDIS CONNECTED')
        pubsub = r.pubsub()
        await pubsub.subscribe('scan_progress:test')
        await r.publish('scan_progress:test', '{"type":"test"}')
        msg = await asyncio.wait_for(
            pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0),
            timeout=3
        )
        print(f'PUBSUB WORKS: {msg}' if msg else 'PUBSUB: no message received')
        await pubsub.close()
    except Exception as e:
        print(f'REDIS FAILED: {e}')

async def test_sandbox():
    try:
        from app.core.sandbox import sandbox
        result = await sandbox.execute('print("hello from sandbox")', language='python', timeout=10)
        print('SANDBOX RESULT:', result)
    except Exception as e:
        print('SANDBOX FAILED:', e)

async def test_persistence():
    try:
        from app.database import async_session_factory
        from app.repositories import ScanRepository
        async with async_session_factory() as db:
            repo = ScanRepository(db)
            scans = await repo.list_scans(limit=5)
            print(f'SCANS IN DB: {len(scans)}')
            for s in scans:
                print(f'  - {s.scan_type} | {s.target} | {s.status}')
    except Exception as e:
        print('PERSISTENCE TEST FAILED:', e)

async def main():
    print("--- CHECK 11: WebSocket test ---")
    await test_ws()
    print("\n--- CHECK 12: Redis Pub/Sub ---")
    await test_redis()
    print("\n--- CHECK 13: Docker sandbox test ---")
    await test_sandbox()
    print("\n--- CHECK 14: Task persistence test ---")
    await test_persistence()

if __name__ == "__main__":
    asyncio.run(main())
