# Airlock vs. picklescan

Code-execution detection on pickle artifacts.

## adversarial (14 artifacts)

- Airlock flagged code execution: **14/14**
- picklescan flagged code execution: **10/14**

| Artifact | Airlock | picklescan |
| --- | :---: | :---: |
| reduce_proto0 | flag | flag |
| reduce_proto1 | flag | flag |
| reduce_proto2 | flag | flag |
| reduce_proto3 | flag | flag |
| reduce_proto4 | flag | flag |
| reduce_proto5 | flag | flag |
| stack_global | flag | flag |
| stack_global_framed | flag | flag |
| gzip_bin | flag | miss |
| zlib_bin | flag | miss |
| base64_nested | flag | miss |
| npy_object | flag | n/a |
| torch_zip | flag | flag |
| disguised_safetensors | flag | flag |

## real-models (18 artifacts)

- Airlock flagged code execution: **0/18**
- picklescan flagged code execution: **0/18**

| Artifact | Airlock | picklescan |
| --- | :---: | :---: |
| sshleifer__tiny-gpt2/pytorch_model.bin | miss | miss |
| prajjwal1__bert-tiny/pytorch_model.bin | miss | miss |
| hf-internal-testing__tiny-random-gpt2/pytorch_model.bin | miss | miss |
| hf-internal-testing__tiny-random-BertModel/pytorch_model.bin | miss | miss |
| hf-internal-testing__tiny-random-DistilBertModel/pytorch_model.bin | miss | miss |
| hf-internal-testing__tiny-random-RobertaModel/pytorch_model.bin | miss | miss |
| hf-internal-testing__tiny-random-t5/pytorch_model.bin | miss | miss |
| hf-internal-testing__tiny-random-BartModel/pytorch_model.bin | miss | miss |
| hf-internal-testing__tiny-random-GPT2LMHeadModel/pytorch_model.bin | miss | miss |
| hf-internal-testing__tiny-random-AlbertModel/pytorch_model.bin | miss | miss |
| hf-internal-testing__tiny-random-MobileBertModel/pytorch_model.bin | miss | miss |
| hf-internal-testing__tiny-random-ElectraModel/pytorch_model.bin | miss | miss |
| hf-internal-testing__tiny-random-DebertaModel/pytorch_model.bin | miss | miss |
| hf-internal-testing__tiny-random-MistralForCausalLM/pytorch_model.bin | miss | miss |
| hf-internal-testing__tiny-random-GPTNeoXForCausalLM/pytorch_model.bin | miss | miss |
| hf-internal-testing__tiny-random-OPTForCausalLM/pytorch_model.bin | miss | miss |
| hf-internal-testing__tiny-random-BloomModel/pytorch_model.bin | miss | miss |
| hf-internal-testing__tiny-random-CLIPModel/pytorch_model.bin | miss | miss |


