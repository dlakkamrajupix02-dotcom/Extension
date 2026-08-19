# Getting Started with Payload Shield

## Backend Setup (FastAPI)

```python
from fastapi import FastAPI
from payload_shield import PayloadShieldDependency, SessionStore

app = FastAPI()
```

## Frontend Setup (React)

```tsx
import { PayloadShieldProvider, useEncryptedFetch } from 'payload-shield-client';
```
