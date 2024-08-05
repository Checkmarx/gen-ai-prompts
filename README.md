# AI Prompts for various AI use cases accross CxOne
This repository contains a collection of AI prompt builders for various AI use cases across CxOne.
## AI Remediation for SAST Results
This creates a prompt for an AI LLM model to remediate a SAST result. 
The prompt is created by building code snippets that combine the SAST result nodes with the actual code from the source repository.
Sending the prompt to the AI model will generate a remediation suggestion that includes: 
1. confidence score (between 0 and 100) - this score indicates how confident the AI model is about exploitation risk of the result vulnerability
2. explanation of the confidence score - what causes the AI model to suggest the confidence score
3. remediation suggestion - the actual code snippet that fixes the vulnerability so that a developer can copy-paste into the source code

The form of the response is: 
```
**CONFIDENCE**: [0-100]

**EXPLANATION**: [explanation of the confidence score]

**PROPOSED REMEDIATION**: [code snippet]
```
