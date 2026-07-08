# Airlock vs. open pickle scanners

Code-execution detection on pickle artifacts. Scanners compared: Airlock, picklescan, modelscan, fickling.

## adversarial (14 artifacts)

- Airlock flagged code execution: **14/14**
- picklescan flagged code execution: **11/14**
- modelscan flagged code execution: **9/14**
- fickling flagged code execution: **9/14**

| Artifact | Airlock | picklescan | modelscan | fickling |
| --- | :---: | :---: | :---: | :---: |
| reduce_proto0 | flag | flag | flag | flag |
| reduce_proto1 | flag | flag | flag | flag |
| reduce_proto2 | flag | flag | flag | flag |
| reduce_proto3 | flag | flag | flag | flag |
| reduce_proto4 | flag | flag | flag | flag |
| reduce_proto5 | flag | flag | flag | flag |
| stack_global | flag | flag | flag | flag |
| stack_global_framed | flag | flag | flag | flag |
| gzip_bin | flag | miss | miss | n/a |
| zlib_bin | flag | miss | miss | n/a |
| base64_nested | flag | miss | miss | miss |
| npy_object | flag | flag | miss | n/a |
| torch_zip | flag | flag | flag | n/a |
| disguised_safetensors | flag | flag | miss | flag |

## real-models (18 artifacts)

- Airlock flagged code execution: **0/18**
- picklescan flagged code execution: **0/18**
- modelscan flagged code execution: **0/18**
- fickling flagged code execution: **0/18**

| Artifact | Airlock | picklescan | modelscan | fickling |
| --- | :---: | :---: | :---: | :---: |
| sshleifer__tiny-gpt2/pytorch_model.bin | miss | miss | miss | miss |
| prajjwal1__bert-tiny/pytorch_model.bin | miss | miss | miss | n/a |
| hf-internal-testing__tiny-random-gpt2/pytorch_model.bin | miss | miss | miss | n/a |
| hf-internal-testing__tiny-random-BertModel/pytorch_model.bin | miss | miss | miss | n/a |
| hf-internal-testing__tiny-random-DistilBertModel/pytorch_model.bin | miss | miss | miss | n/a |
| hf-internal-testing__tiny-random-RobertaModel/pytorch_model.bin | miss | miss | miss | n/a |
| hf-internal-testing__tiny-random-t5/pytorch_model.bin | miss | miss | miss | n/a |
| hf-internal-testing__tiny-random-BartModel/pytorch_model.bin | miss | miss | miss | n/a |
| hf-internal-testing__tiny-random-GPT2LMHeadModel/pytorch_model.bin | miss | miss | miss | n/a |
| hf-internal-testing__tiny-random-AlbertModel/pytorch_model.bin | miss | miss | miss | n/a |
| hf-internal-testing__tiny-random-MobileBertModel/pytorch_model.bin | miss | miss | miss | n/a |
| hf-internal-testing__tiny-random-ElectraModel/pytorch_model.bin | miss | miss | miss | n/a |
| hf-internal-testing__tiny-random-DebertaModel/pytorch_model.bin | miss | miss | miss | n/a |
| hf-internal-testing__tiny-random-MistralForCausalLM/pytorch_model.bin | miss | miss | miss | n/a |
| hf-internal-testing__tiny-random-GPTNeoXForCausalLM/pytorch_model.bin | miss | miss | miss | n/a |
| hf-internal-testing__tiny-random-OPTForCausalLM/pytorch_model.bin | miss | miss | miss | n/a |
| hf-internal-testing__tiny-random-BloomModel/pytorch_model.bin | miss | miss | miss | n/a |
| hf-internal-testing__tiny-random-CLIPModel/pytorch_model.bin | miss | miss | miss | n/a |


