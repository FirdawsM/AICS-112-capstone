# Individual reflection

## What I built
I completed Labs 2 to 4 in the pipeline, added tests, wrote the approval-gated playbook, ran the training set to precision 1.0 and recall 1.0, then ran the blind capstone dataset and decided on SOAR-0006 myself.

## What did not work first time
The Ollama call timed out at 90 seconds and the console fell back to the offline model. I recorded the fallback instead of hiding it, then raised the timeout to prove the Ollama path worked.

## My approval decisions on SOAR-0006
- isolate_endpoint: approved (dry run). REASON: [write why]
- disable_identity: denied. REASON: [write why]
- revoke_oauth_grant: denied. REASON: [write why]

## Limits I accept
The data is synthetic, the model is small, and a perfect score on the training set does not prove it works on real traffic. [Add one limit you actually noticed.]

## What I would change
[Pick two from your improvement backlog and say why.]
