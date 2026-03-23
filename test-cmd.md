```
curl -s -m 15 -X POST http://64.186.230.45:3000/v1/messages -H "Content-Type: application/json" -H "x-api-key: sk-nhzwBySIW75TnK5smilS4aQ7BYiXlSr2DAY2B4gI89rZQqLL" -H "anthropic-version: 2023-06-01" -d '{"model":"claude-sonnet-4-5","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}'
```
