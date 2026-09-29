"""Exercise a running container: auth, upload, native analysis, plans and result downloads."""

import json
import runpy
import ssl
import sys
import tempfile
from pathlib import Path

import httpx

from chainsaw_mcp.transfers import load_private_key, load_public_key

client = runpy.run_path(str(Path(__file__).with_name("remote-client.py")))
url, token_file, ca_file, signing_key_file, trusted_key_file = sys.argv[1:]
signing_key = load_private_key(Path(signing_key_file))
trusted_key = load_public_key(Path(trusted_key_file))
assert (
    httpx.post(url, json={}, verify=ssl.create_default_context(cafile=ca_file)).status_code == 401
)
with tempfile.TemporaryDirectory() as work:
    directory = Path(work)
    source = directory / "synthetic.json"
    source.write_text('{"Event":{"System":{"EventID":4104}}}')
    with client["Remote"](url, Path(token_file).read_text().strip(), ca_file=ca_file) as remote:
        uploaded = client["upload"](remote, source, signing_key)
        assert uploaded["complete"]
        result = remote.call("chainsaw_dump", {"paths": [uploaded["path"]]})
        assert result["total"] == 1
        plan = remote.call(
            "chainsaw_plan",
            {
                "steps": [
                    {
                        "tool": "chainsaw_dump",
                        "arguments": {"paths": [uploaded["path"]]},
                    }
                ]
            },
        )
        assert plan["mode"] == "planned"
        replay = remote.call("chainsaw_reproduce", {"handles": [result["handle"]]})
        client["download"](remote, replay["script_handle"], directory / "replay.sh", trusted_key)
        client["download"](
            remote, replay["manifest_handle"], directory / "manifest.jsonl", trusted_key
        )
        assert "--jsonl" in (directory / "replay.sh").read_text()
        manifest = [
            json.loads(line) for line in (directory / "manifest.jsonl").read_text().splitlines()
        ]
        assert manifest[0]["mode"] == "recorded"
print("Verified HTTPS, signed upload/download, native dump, plan and reproduction passed.")
